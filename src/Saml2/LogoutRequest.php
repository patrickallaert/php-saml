<?php
namespace OneLogin\Saml2;

use DOMDocument;
use DOMElement;
use Exception;
use RobRichards\XMLSecLibs\XMLSecurityKey;

/**
 * SAML 2 Logout Request
 */
class LogoutRequest
{
    /**
     * @var string
     */
    public $id;

    /**
     * @var Settings
     */
    protected $settings;

    /**
     * SAML Logout Request
     *
     * @var string
     */
    protected $logoutRequest;

    /**
     * After execute a validation process, this var contains the cause
     *
     * @var ?Exception
     */
    private $error;

    /**
     * @param ?string $request               A UUEncoded Logout Request.
     * @param ?string $nameId                The NameID that will be set in the LogoutRequest.
     * @param ?string $sessionIndex          The SessionIndex (taken from the SAML Response in the SSO process).
     * @param ?string $nameIdFormat          The NameID Format will be set in the LogoutRequest.
     * @param ?string $nameIdNameQualifier   The NameID NameQualifier will be set in the LogoutRequest.
     * @param ?string $nameIdSPNameQualifier The NameID SP NameQualifier will be set in the LogoutRequest.
     */
    public function __construct(
        Settings $settings,
        ?string $request = null,
        ?string $nameId = null,
        ?string $sessionIndex = null,
        ?string $nameIdFormat = null,
        ?string $nameIdNameQualifier = null,
        ?string $nameIdSPNameQualifier = null
    ) {
        $this->settings = $settings;

        $baseURL = $this->settings->getBaseURL();
        if (!empty($baseURL)) {
            Utils::setBaseURL($baseURL);
        }

        if ($request === null || empty($request)) {
            $id = Utils::generateUniqueID();
            $this->id = $id;

            $issueInstant = Utils::parseTime2SAML(time());

            if (!empty($nameId)) {
                $spNameIdFormat = $this->settings->getSPNameIDFormat();
                if (empty($nameIdFormat)
                    && $spNameIdFormat !== Constants::NAMEID_UNSPECIFIED) {
                    $nameIdFormat = $spNameIdFormat;
                }
            } else {
                $nameId = $this->settings->getIdPEntityId();
                $nameIdFormat = Constants::NAMEID_ENTITY;
            }

            /* From saml-core-2.0-os 8.3.6, when the entity Format is used:
               "The NameQualifier, SPNameQualifier, and SPProvidedID attributes MUST be omitted.
            */
            if (!empty($nameIdFormat) && $nameIdFormat === Constants::NAMEID_ENTITY) {
                $nameIdNameQualifier = null;
                $nameIdSPNameQualifier = null;
            }

            // NameID Format UNSPECIFIED omitted
            if (!empty($nameIdFormat) && $nameIdFormat === Constants::NAMEID_UNSPECIFIED) {
                $nameIdFormat = null;
            }

            $nameIdObj = Utils::generateNameId(
                $nameId,
                $nameIdSPNameQualifier,
                $nameIdFormat,
                $this->settings->getSecurityNameIdEncrypted() ? $this->settings->getIdPOneEncryptionCertificate() : null,
                $nameIdNameQualifier
            );

            $sessionIndexStr = isset($sessionIndex) ? "<samlp:SessionIndex>{$sessionIndex}</samlp:SessionIndex>" : "";

            $spEntityId = htmlspecialchars($this->settings->getSPEntityId(), ENT_QUOTES);
            $sloServiceUrl = $this->settings->getIdPSingleLogoutServiceUrl();
            $logoutRequest = <<<LOGOUTREQUEST
<samlp:LogoutRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{$id}"
    Version="2.0"
    IssueInstant="{$issueInstant}"
    Destination="$sloServiceUrl">
    <saml:Issuer>{$spEntityId}</saml:Issuer>
    {$nameIdObj}
    {$sessionIndexStr}
</samlp:LogoutRequest>
LOGOUTREQUEST;
        } else {
            $decoded = base64_decode($request);
            // We try to inflate
            $inflated = @gzinflate($decoded);
            $logoutRequest = $inflated !== false ? $inflated : $decoded;
            $this->id = static::getID($logoutRequest);
        }
        $this->logoutRequest = $logoutRequest;
    }

    /**
     * Returns the Logout Request defated, base64encoded, unsigned
     *
     * @param bool|null $deflate Whether or not we should 'gzdeflate' the request body before we return it.
     *
     * @return string Deflated base64 encoded Logout Request
     */
    public function getRequest(?bool $deflate = null): string
    {
        $subject = $this->logoutRequest;

        if ($deflate === null) {
            $deflate = $this->settings->shouldCompressRequests();
        }

        if ($deflate) {
            $subject = gzdeflate($this->logoutRequest);
        }

        return base64_encode($subject);
    }

    /**
     * @throws Error
     */
    public static function getID(string $request): string
    {
        try {
            Utils::loadXML($dom = new DOMDocument(), $request);
        } catch (Exception $e) {
            throw new Error(
                "LogoutRequest could not be processed",
                Error::SAML_LOGOUTREQUEST_INVALID
            );
        }

        return $dom->documentElement->getAttribute('ID');
    }

    /**
     * Gets the NameID Data of the the Logout Request.
     *
     * @return array{Value:string,Format?:string,NameQualifier?:string,SPNameQualifier?:string}
     *
     * @throws Error
     * @throws Exception
     * @throws ValidationError
     */
    public static function getNameIdData(string $request, ?string $key = null): array
    {
        $dom = new DOMDocument();
        Utils::loadXML($dom, $request);

        $encryptedEntries = Utils::query($dom, '/samlp:LogoutRequest/saml:EncryptedID');

        if ($encryptedEntries->length === 1) {
            if (empty($key)) {
                throw new Error(
                    "Private Key is required in order to decrypt the NameID, check settings",
                    Error::PRIVATE_KEY_NOT_FOUND
                );
            }

            $seckey = new XMLSecurityKey(XMLSecurityKey::RSA_1_5, ['type' => 'private']);
            $seckey->loadKey($key);

            $encryptedEntry = $encryptedEntries->item(0);
            assert($encryptedEntry instanceof DOMElement);
            $encryptedData = $encryptedEntry->getElementsByTagName('EncryptedData')->item(0);
            assert($encryptedData instanceof DOMElement);
            $nameId = Utils::decryptElement($encryptedData, $seckey);
        } else {
            $entries = Utils::query($dom, '/samlp:LogoutRequest/saml:NameID');
            if ($entries->length === 1) {
                $nameId = $entries->item(0);
            }
        }

        if (!isset($nameId)) {
            throw new ValidationError(
                "NameID not found in the Logout Request",
                ValidationError::NO_NAMEID
            );
        }

        $nameIdData = [];
        $nameIdData['Value'] = $nameId->nodeValue;
        foreach (['Format', 'SPNameQualifier', 'NameQualifier'] as $attr) {
            if ($nameId->hasAttribute($attr)) {
                $nameIdData[$attr] = $nameId->getAttribute($attr);
            }
        }

        return $nameIdData;
    }

    /**
     * @throws Error
     * @throws Exception
     * @throws ValidationError
     */
    public static function getNameId(string $request, ?string $key = null): string
    {
        return self::getNameIdData($request, $key)['Value'];
    }

    /**
     * @throws Exception
     */
    public static function getIssuer(DOMDocument $request): ?string
    {
        $issuerNodes = Utils::query($request, '/samlp:LogoutRequest/saml:Issuer');
        if ($issuerNodes->length === 1) {
            return $issuerNodes->item(0)->textContent;
        }
        return null;
    }

    /**
     * Gets the SessionIndexes from the Logout Request.
     * Notice: Our Constructor only support 1 SessionIndex but this parser
     *         extracts an array of all the  SessionIndex found on a
     *         Logout Request, that could be many.
     *
     * @throws Exception
     */
    public static function getSessionIndexes(string $request): array
    {
        Utils::loadXML($dom = new DOMDocument(), $request);

        $sessionIndexes = [];
        $sessionIndexNodes = Utils::query($dom, '/samlp:LogoutRequest/samlp:SessionIndex');
        foreach ($sessionIndexNodes as $sessionIndexNode) {
            $sessionIndexes[] = $sessionIndexNode->textContent;
        }
        return $sessionIndexes;
    }

    public function isValid(bool $retrieveParametersFromServer = false): bool
    {
        $this->error = null;
        try {
            $dom = new DOMDocument();
            Utils::loadXML($dom, $this->logoutRequest);

            if ($this->settings->isStrict()) {
                if ($this->settings->getSecurityWantXMLValidation() &&
                    !Utils::validateXML($dom, 'saml-schema-protocol-2.0.xsd')) {
                    throw new ValidationError(
                        "Invalid SAML Logout Request. Not match the saml-schema-protocol-2.0.xsd",
                        ValidationError::INVALID_XML_FORMAT
                    );
                }

                // Check NotOnOrAfter
                if ($dom->documentElement->hasAttribute('NotOnOrAfter') &&
                    Utils::parseSAML2Time($dom->documentElement->getAttribute('NotOnOrAfter')) <= time()) {
                    throw new ValidationError(
                        "Could not validate timestamp: expired. Check system clock.",
                        ValidationError::RESPONSE_EXPIRED
                    );
                }

                // Check destination
                if ($dom->documentElement->hasAttribute('Destination')) {
                    $destination = $dom->documentElement->getAttribute('Destination');
                    $currentURL = Utils::getSelfRoutedURLNoQuery();

                    if (!empty($destination) && strpos($destination, $currentURL) === false) {
                        throw new ValidationError(
                            "The LogoutRequest was received at $currentURL instead of $destination",
                            ValidationError::WRONG_DESTINATION
                        );
                    }
                }

                // Check issuer
                $issuer = static::getIssuer($dom);
                if (!empty($issuer) && $issuer !== $this->settings->getIdPEntityId()) {
                    throw new ValidationError(
                        "Invalid issuer in the Logout Request",
                        ValidationError::WRONG_ISSUER
                    );
                }

                if ($this->settings->getSecurityWantMessagesSigned() && !isset($_GET['Signature'])) {
                    throw new ValidationError(
                        "The Message of the Logout Request is not signed and the SP require it",
                        ValidationError::NO_SIGNED_MESSAGE
                    );
                }
            }

            if (isset($_GET['Signature']) &&
                !Utils::validateBinarySign("SAMLRequest", $_GET, $this->settings, $retrieveParametersFromServer)) {
                throw new ValidationError(
                    "Signature validation failed. Logout Request rejected",
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
     * After execute a validation process, if fails this method returns the Exception of the cause
     */
    public function getErrorException(): Exception
    {
        return $this->error;
    }

    /**
     * Returns the XML that will be sent as part of the request
     * or that was received at the SP
     */
    public function getXML(): string
    {
        return $this->logoutRequest;
    }
}
