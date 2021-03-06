<?php
namespace Saml2;

use DOMDocument;
use DOMElement;
use Exception;

/**
 * SAML 2 Logout Response
 */
class LogoutResponse
{
    /**
     * Contains the ID of the Logout Response
     *
     * @var string
     */
    public $id;

    /**
     * Object that represents the setting info
     *
     * @var Settings
     */
    protected $settings;

    /**
     * The decoded, unprocessed XML response provided to the constructor.
     *
     * @var string|null
     */
    protected $logoutResponse;

    /**
     * A DOMDocument class loaded from the SAML LogoutResponse.
     *
     * @var DOMDocument
     */
    public $document;

    /**
     * After execute a validation process, if it fails, this var contains the cause
     *
     * @var Exception|null
     */
    private $error;

    /**
     * Constructs a Logout Response object (Initialize params from settings and if provided
     * load the Logout Response.
     *
     * @param Settings $settings Settings.
     * @param string|null             $response An UUEncoded SAML Logout response from the IdP.
     *
     * @throws Error
     * @throws Exception
     *
     */
    public function __construct(Settings $settings, ?string $response = null)
    {
        $this->settings = $settings;

        $baseURL = $this->settings->getBaseURL();
        if (!empty($baseURL)) {
            Utils::setBaseURL($baseURL);
        }

        if (!empty($response)) {
            $decoded = base64_decode($response);
            $inflated = @gzinflate($decoded);
            $this->logoutResponse = $inflated !== false ? $inflated : $decoded;
            $this->document = new DOMDocument();
            try {
                Utils::loadXML($this->document, $this->logoutResponse);
            } catch (Exception $e) {
                throw new Error(
                    "LogoutResponse could not be processed",
                    Error::SAML_LOGOUTRESPONSE_INVALID
                );
            }

            if ($this->document->documentElement->hasAttribute('ID')) {
                $this->id = $this->document->documentElement->getAttribute('ID');
            }
        }
    }

    public function getIssuer(): ?string
    {
        $issuerNodes = Utils::query($this->document, '/samlp:LogoutResponse/saml:Issuer');
        if ($issuerNodes->length === 1) {
            return $issuerNodes->item(0)->textContent;
        }
        return null;
    }

    public function getStatus(): ?string
    {
        $entries = Utils::query($this->document, '/samlp:LogoutResponse/samlp:Status/samlp:StatusCode');
        if ($entries->length !== 1) {
            return null;
        }
        $statusCode = $entries->item(0);
        if (!$statusCode instanceof DOMElement) {
            return null;
        }
        return $statusCode->getAttribute('Value');
    }

    /**
     * Determines if the SAML LogoutResponse is valid
     *
     * @param string|null $requestId                    The ID of the LogoutRequest sent by this SP to the IdP
     * @param bool        $retrieveParametersFromServer True if we want to use parameters from $_SERVER to validate the signature
     */
    public function isValid(?string $requestId = null, bool $retrieveParametersFromServer = false): bool
    {
        $this->error = null;
        try {
            if ($this->settings->isStrict()) {
                if ($this->settings->getSecurityWantXMLValidation() &&
                    !Utils::validateXML($this->document, 'saml-schema-protocol-2.0.xsd')) {
                    throw new ValidationError(
                        "Invalid SAML Logout Response. Not match the saml-schema-protocol-2.0.xsd",
                        ValidationError::INVALID_XML_FORMAT
                    );
                }

                // Check if the InResponseTo of the Logout Response matches the ID of the Logout Request (requestId) if provided
                if (isset($requestId) && $this->document->documentElement->hasAttribute('InResponseTo')) {
                    $inResponseTo = $this->document->documentElement->getAttribute('InResponseTo');
                    if ($requestId !== $inResponseTo) {
                        throw new ValidationError(
                            "The InResponseTo of the Logout Response: $inResponseTo, " .
                            "does not match the ID of the Logout request sent by the SP: $requestId",
                            ValidationError::WRONG_INRESPONSETO
                        );
                    }
                }

                // Check issuer
                $issuer = $this->getIssuer();
                if (!empty($issuer) && $issuer !== $this->settings->getIdPEntityId()) {
                    throw new ValidationError(
                        "Invalid issuer in the Logout Response",
                        ValidationError::WRONG_ISSUER
                    );
                }

                $currentURL = Utils::getSelfRoutedURLNoQuery();

                // Check destination
                if ($this->document->documentElement->hasAttribute('Destination')) {
                    $destination = $this->document->documentElement->getAttribute('Destination');
                    if (!empty($destination) && strpos($destination, $currentURL) === false) {
                        throw new ValidationError(
                            "The LogoutResponse was received at $currentURL instead of $destination",
                            ValidationError::WRONG_DESTINATION
                        );
                    }
                }

                if ($this->settings->getSecurityWantMessagesSigned() && !isset($_GET['Signature'])) {
                    throw new ValidationError(
                        "The Message of the Logout Response is not signed and the SP requires it",
                        ValidationError::NO_SIGNED_MESSAGE
                    );
                }
            }

            if (isset($_GET['Signature']) &&
                !Utils::validateBinarySign("SAMLResponse", $_GET, $this->settings, $retrieveParametersFromServer)) {
                throw new ValidationError(
                    "Signature validation failed. Logout Response rejected",
                    ValidationError::INVALID_SIGNATURE
                );
            }
            return true;
        } catch (Exception $e) {
            $this->error = $e;
            return false;
        }
    }

    /**
     * Generates a Logout Response object.
     *
     * @param string $inResponseTo InResponseTo value for the Logout Response.
     */
    public function build(string $inResponseTo): void
    {
        $sloServiceUrl = $this->settings->getIdPSingleLogoutServiceUrl();

        $this->id = Utils::generateUniqueID();
        $issueInstant = Utils::parseTime2SAML(time());

        $spEntityId = htmlspecialchars($this->settings->getSPEntityId(), ENT_QUOTES);
        $this->logoutResponse = <<<LOGOUTRESPONSE
<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                  ID="{$this->id}"
                  Version="2.0"
                  IssueInstant="$issueInstant"
                  Destination="$sloServiceUrl"
                  InResponseTo="$inResponseTo"
                  >
    <saml:Issuer>$spEntityId</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
    </samlp:Status>
</samlp:LogoutResponse>
LOGOUTRESPONSE;
    }

    public function getResponse(?bool $deflate = null): string
    {
        $logoutResponse = $this->logoutResponse;

        if ($deflate === null) {
            $deflate = $this->settings->shouldCompressResponses();
        }

        if ($deflate) {
            $logoutResponse = gzdeflate($this->logoutResponse);
        }
        return base64_encode($logoutResponse);
    }

    /**
     * After execute a validation process, if fails this method returns the cause.
     */
    public function getErrorException(): Exception
    {
        return $this->error;
    }
}
