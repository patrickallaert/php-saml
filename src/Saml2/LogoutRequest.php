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
     * @param Settings $settings            Settings
     * @param string|null             $request             A UUEncoded Logout Request.
     * @param string|null             $nameId              The NameID that will be set in the LogoutRequest.
     * @param string|null             $sessionIndex        The SessionIndex (taken from the SAML Response in the SSO process).
     * @param string|null             $nameIdFormat        The NameID Format will be set in the LogoutRequest.
     * @param string|null             $nameIdNameQualifier The NameID NameQualifier will be set in the LogoutRequest.
     * @param string|null             $nameIdSPNameQualifier The NameID SP NameQualifier will be set in the LogoutRequest.
     */
    public function __construct(Settings $settings, ?string $request = null, ?string $nameId = null, ?string $sessionIndex = null, ?string $nameIdFormat = null, ?string $nameIdNameQualifier = null, ?string $nameIdSPNameQualifier = null)
    {
        $this->settings = $settings;

        $baseURL = $this->settings->getBaseURL();
        if (!empty($baseURL)) {
            Utils::setBaseURL($baseURL);
        }

        if (!isset($request) || empty($request)) {
            $spData = $this->settings->getSPData();
            $idpData = $this->settings->getIdPData();
            $security = $this->settings->getSecurityData();

            $id = Utils::generateUniqueID();
            $this->id = $id;

            $issueInstant = Utils::parseTime2SAML(time());

            $cert = null;
            if (isset($security['nameIdEncrypted']) && $security['nameIdEncrypted']) {
                $existsMultiX509Enc = isset($idpData['x509certMulti']) && isset($idpData['x509certMulti']['encryption']) && !empty($idpData['x509certMulti']['encryption']);

                if ($existsMultiX509Enc) {
                    $cert = $idpData['x509certMulti']['encryption'][0];
                } else {
                    $cert = $idpData['x509cert'];
                }
            }

            if (!empty($nameId)) {
                if (empty($nameIdFormat)
                    && $spData['NameIDFormat'] !== Constants::NAMEID_UNSPECIFIED) {
                    $nameIdFormat = $spData['NameIDFormat'];
                }
            } else {
                $nameId = $idpData['entityId'];
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
                $cert,
                $nameIdNameQualifier
            );

            $sessionIndexStr = isset($sessionIndex) ? "<samlp:SessionIndex>{$sessionIndex}</samlp:SessionIndex>" : "";

            $spEntityId = htmlspecialchars($spData['entityId'], ENT_QUOTES);
            $logoutRequest = <<<LOGOUTREQUEST
<samlp:LogoutRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{$id}"
    Version="2.0"
    IssueInstant="{$issueInstant}"
    Destination="{$idpData['singleLogoutService']['url']}">
    <saml:Issuer>{$spEntityId}</saml:Issuer>
    {$nameIdObj}
    {$sessionIndexStr}
</samlp:LogoutRequest>
LOGOUTREQUEST;
        } else {
            $decoded = base64_decode($request);
            // We try to inflate
            $inflated = @gzinflate($decoded);
            if ($inflated !== false) {
                $logoutRequest = $inflated;
            } else {
                $logoutRequest = $decoded;
            }
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
    public function getRequest($deflate = null)
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
     * Returns the ID of the Logout Request.
     *
     * @param string|DOMDocument $request Logout Request Message
     *
     * @return string ID
     *
     * @throws Error
     */
    public static function getID($request)
    {
        if ($request instanceof DOMDocument) {
            $dom = $request;
        } else {
            $dom = Utils::loadXML(new DOMDocument(), $request);
        }

        if ($dom === false) {
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
     * @param string|DOMDocument $request Logout Request Message
     * @param string|null        $key     The SP key
     *
     * @return array Name ID Data (Value, Format, NameQualifier, SPNameQualifier)
     *
     * @throws Error
     * @throws Exception
     * @throws ValidationError
     */
    public static function getNameIdData($request, $key = null)
    {
        if ($request instanceof DOMDocument) {
            $dom = $request;
        } else {
            $dom = new DOMDocument();
            $dom = Utils::loadXML($dom, $request);
        }

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
     * @param string|DOMDocument $request Logout Request Message
     *
     * @return string Name ID Value
     *
     * @throws Error
     * @throws Exception
     * @throws ValidationError
     */
    public static function getNameId($request, ?string $key = null)
    {
        $nameId = self::getNameIdData($request, $key);
        return $nameId['Value'];
    }

    /**
     * Gets the Issuer of the Logout Request.
     *
     * @param string|DOMDocument $request Logout Request Message
     *
     * @return string|null $issuer The Issuer
     *
     * @throws Exception
     */
    public static function getIssuer($request)
    {
        if ($request instanceof DOMDocument) {
            $dom = $request;
        } else {
            $dom = Utils::loadXML(new DOMDocument(), $request);
        }

        $issuer = null;
        $issuerNodes = Utils::query($dom, '/samlp:LogoutRequest/saml:Issuer');
        if ($issuerNodes->length === 1) {
            $issuer = $issuerNodes->item(0)->textContent;
        }
        return $issuer;
    }

    /**
     * Gets the SessionIndexes from the Logout Request.
     * Notice: Our Constructor only support 1 SessionIndex but this parser
     *         extracts an array of all the  SessionIndex found on a
     *         Logout Request, that could be many.
     *
     * @param string|DOMDocument $request Logout Request Message
     *
     * @throws Exception
     */
    public static function getSessionIndexes($request): array
    {
        if ($request instanceof DOMDocument) {
            $dom = $request;
        } else {
            $dom = Utils::loadXML(new DOMDocument(), $request);
        }

        $sessionIndexes = [];
        $sessionIndexNodes = Utils::query($dom, '/samlp:LogoutRequest/samlp:SessionIndex');
        foreach ($sessionIndexNodes as $sessionIndexNode) {
            $sessionIndexes[] = $sessionIndexNode->textContent;
        }
        return $sessionIndexes;
    }

    /**
     * Checks if the Logout Request recieved is valid.
     *
     * @param bool $retrieveParametersFromServer True if we want to use parameters from $_SERVER to validate the signature
     *
     * @return bool If the Logout Request is or not valid
     *
     * @throws Exception
     * @throws ValidationError
     */
    public function isValid(bool $retrieveParametersFromServer = false)
    {
        $this->error = null;
        try {
            $dom = new DOMDocument();
            $dom = Utils::loadXML($dom, $this->logoutRequest);

            $idpData = $this->settings->getIdPData();
            $idPEntityId = $idpData['entityId'];

            if ($this->settings->isStrict()) {
                $security = $this->settings->getSecurityData();

                if ($security['wantXMLValidation']) {
                    $res = Utils::validateXML($dom, 'saml-schema-protocol-2.0.xsd', $this->settings->isDebugActive());
                    if (!$res instanceof DOMDocument) {
                        throw new ValidationError(
                            "Invalid SAML Logout Request. Not match the saml-schema-protocol-2.0.xsd",
                            ValidationError::INVALID_XML_FORMAT
                        );
                    }
                }

                $currentURL = Utils::getSelfRoutedURLNoQuery();

                // Check NotOnOrAfter
                if ($dom->documentElement->hasAttribute('NotOnOrAfter')) {
                    $na = Utils::parseSAML2Time($dom->documentElement->getAttribute('NotOnOrAfter'));
                    if ($na <= time()) {
                        throw new ValidationError(
                            "Could not validate timestamp: expired. Check system clock.",
                            ValidationError::RESPONSE_EXPIRED
                        );
                    }
                }

                // Check destination
                if ($dom->documentElement->hasAttribute('Destination')) {
                    $destination = $dom->documentElement->getAttribute('Destination');
                    if (!empty($destination) && strpos($destination, $currentURL) === false) {
                        throw new ValidationError(
                            "The LogoutRequest was received at $currentURL instead of $destination",
                            ValidationError::WRONG_DESTINATION
                        );
                    }
                }

                // Check issuer
                $issuer = static::getIssuer($dom);
                if (!empty($issuer) && $issuer !== $idPEntityId) {
                    throw new ValidationError(
                        "Invalid issuer in the Logout Request",
                        ValidationError::WRONG_ISSUER
                    );
                }

                if ($security['wantMessagesSigned'] && !isset($_GET['Signature'])) {
                    throw new ValidationError(
                        "The Message of the Logout Request is not signed and the SP require it",
                        ValidationError::NO_SIGNED_MESSAGE
                    );
                }
            }

            if (isset($_GET['Signature'])) {
                if (!Utils::validateBinarySign("SAMLRequest", $_GET, $idpData, $retrieveParametersFromServer)) {
                    throw new ValidationError(
                        "Signature validation failed. Logout Request rejected",
                        ValidationError::INVALID_SIGNATURE
                    );
                }
            }

            return true;
        } catch (Exception $e) {
            $this->error = $e;
            if ($this->settings->isDebugActive()) {
                echo htmlentities($this->error->getMessage());
            }
            return false;
        }
    }

    /**
     * After execute a validation process, if fails this method returns the Exception of the cause
     */
    public function getErrorException(): ?Exception
    {
        return $this->error;
    }

    /**
     * After execute a validation process, if fails this method returns the cause
     *
     * @return null|string Error reason
     */
    public function getError()
    {
        $errorMsg = null;
        if (isset($this->error)) {
            $errorMsg = htmlentities($this->error->getMessage());
        }
        return $errorMsg;
    }

    /**
     * Returns the XML that will be sent as part of the request
     * or that was received at the SP
     *
     * @return string
     */
    public function getXML()
    {
        return $this->logoutRequest;
    }
}
