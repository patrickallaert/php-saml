<?php
namespace Saml2;

use DOMDocument;
use DOMElement;
use DOMNode;
use DOMNodeList;
use DOMXPath;
use Exception;
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityKey;

/**
 * SAML 2 Authentication Response
 */
class Response
{
    // Value added to the current time in time condition validations
    private const ALLOWED_CLOCK_DRIFT = 180;  // 3 min in seconds
    private const RESPONSE_SIGNATURE_XPATH = "/samlp:Response/ds:Signature";
    private const ASSERTION_SIGNATURE_XPATH = "/samlp:Response/saml:Assertion/ds:Signature";

    /**
     * Settings
     *
     * @var Settings
     */
    protected $settings;

    /**
     * A DOMDocument class loaded from the SAML Response.
     *
     * @var DOMDocument
     */
    public $document;

    /**
     * A DOMDocument class loaded from the SAML Response (Decrypted).
     *
     * @var DOMDocument
     */
    public $decryptedDocument;

    /**
     * The response contains an encrypted assertion.
     *
     * @var bool
     */
    public $encrypted = false;

    /**
     * After validation, if it fail this var has the cause of the problem
     *
     * @var Exception|null
     */
    private $error;

    /**
     * NotOnOrAfter value of a valid SubjectConfirmationData node
     *
     * @var ?int
     */
    private $validSCDNotOnOrAfter;

    /**
     * @throws Exception
     * @throws ValidationError
     */
    public function __construct(Settings $settings, string $response)
    {
        $this->settings = $settings;

        $baseURL = $this->settings->getBaseURL();
        if (!empty($baseURL)) {
            Utils::setBaseURL($baseURL);
        }

        try {
            Utils::loadXML($this->document = new DOMDocument(), base64_decode($response));
        } catch (Exception $e) {
            throw new ValidationError(
                "SAML Response could not be processed",
                ValidationError::INVALID_XML_FORMAT
            );
        }

        // Quick check for the presence of EncryptedAssertion
        if ($this->document->getElementsByTagName('EncryptedAssertion')->length !== 0) {
            $this->decryptedDocument = clone $this->document;
            $this->encrypted = true;
            $this->decryptedDocument = $this->decryptAssertion($this->decryptedDocument);
        }
    }

    /**
     * Determines if the SAML Response is valid using the certificate.
     */
    public function isValid(?string $requestId = null): bool
    {
        $this->error = null;
        try {
            // Check SAML version
            if ($this->document->documentElement->getAttribute('Version') !== '2.0') {
                throw new ValidationError(
                    "Unsupported SAML version",
                    ValidationError::UNSUPPORTED_SAML_VERSION
                );
            }

            if (!$this->document->documentElement->hasAttribute('ID')) {
                throw new ValidationError(
                    "Missing ID attribute on SAML Response",
                    ValidationError::MISSING_ID
                );
            }

            $this->checkStatus();

            if (!$this->validateNumAssertions()) {
                throw new ValidationError(
                    "SAML Response must contain 1 assertion",
                    ValidationError::WRONG_NUMBER_OF_ASSERTIONS
                );
            }

            $signedElements = $this->processSignedElements();

            $hasSignedResponse = in_array('{' . Constants::NS_SAMLP . '}Response', $signedElements);
            $hasSignedAssertion = in_array('{' . Constants::NS_SAML . '}Assertion', $signedElements);

            if ($this->settings->isStrict()) {
                if ($this->settings->getSecurityWantXMLValidation() &&
                    (
                        !Utils::validateXML($this->document, 'saml-schema-protocol-2.0.xsd') ||
                        ($this->encrypted && !Utils::validateXML($this->decryptedDocument, 'saml-schema-protocol-2.0.xsd'))
                    )
                ) {
                    throw new ValidationError(
                        "Invalid SAML Response. Not match the saml-schema-protocol-2.0.xsd",
                        ValidationError::INVALID_XML_FORMAT
                    );
                }

                if ($this->document->documentElement->hasAttribute('InResponseTo')) {
                    $responseInResponseTo = $this->document->documentElement->getAttribute('InResponseTo');
                }

                // Check if the InResponseTo of the Response matches the ID of the AuthNRequest (requestId) if provided
                if (isset($requestId, $responseInResponseTo) && $requestId !== $responseInResponseTo) {
                    throw new ValidationError(
                        "The InResponseTo of the Response: $responseInResponseTo, does not match the ID of the AuthNRequest sent by the SP: $requestId",
                        ValidationError::WRONG_INRESPONSETO
                    );
                }

                if (!$this->encrypted && $this->settings->getSecurityWantAssertionsEncrypted()) {
                    throw new ValidationError(
                        "The assertion of the Response is not encrypted and the SP requires it",
                        ValidationError::NO_ENCRYPTED_ASSERTION
                    );
                }

                if ($this->settings->getSecurityWantNameIdEncrypted() && $this->queryAssertion('/saml:Subject/saml:EncryptedID/xenc:EncryptedData')->length !== 1) {
                    throw new ValidationError(
                        "The NameID of the Response is not encrypted and the SP requires it",
                        ValidationError::NO_ENCRYPTED_NAMEID
                    );
                }

                if ($this->queryAssertion("/saml:Conditions")->length !== 1) {
                    throw new ValidationError(
                        "The Assertion must include a Conditions element",
                        ValidationError::MISSING_CONDITIONS
                    );
                }

                $this->validateTimestamps();

                if ($this->queryAssertion("/saml:AuthnStatement")->length !== 1) {
                    throw new ValidationError(
                        "The Assertion must include an AuthnStatement element",
                        ValidationError::WRONG_NUMBER_OF_AUTHSTATEMENTS
                    );
                }

                // EncryptedAttributes are not supported
                if ($this->queryAssertion('/saml:AttributeStatement/saml:EncryptedAttribute')->length > 0) {
                    throw new ValidationError(
                        "There is an EncryptedAttribute in the Response and this SP not support them",
                        ValidationError::ENCRYPTED_ATTRIBUTES
                    );
                }

                // Check destination
                if ($this->document->documentElement->hasAttribute('Destination')) {
                    $destination = trim($this->document->documentElement->getAttribute('Destination'));
                    if (empty($destination)) {
                        if (!$this->settings->getSecurityRelaxDestinationValidation()) {
                            throw new ValidationError(
                                "The response has an empty Destination value",
                                ValidationError::EMPTY_DESTINATION
                            );
                        }
                    } else {
                        $parsedDestination = parse_url($destination);
                        if ($parsedDestination["host"] !== Utils::getSelfHost() || rtrim($parsedDestination["path"], "/") !== rtrim(parse_url(Utils::getSelfRoutedURLNoQuery(), PHP_URL_PATH), "/")) {
                            throw new ValidationError(
                                "The response destination is supposed to be: $destination",
                                ValidationError::WRONG_DESTINATION
                            );
                        }
                    }
                }

                $validAudiences = [];

                foreach ($this->queryAssertion('/saml:Conditions/saml:AudienceRestriction/saml:Audience') as $entry) {
                    $value = trim($entry->textContent);
                    if (!empty($value)) {
                        $validAudiences[$value] = true;
                    }
                }

                $spEntityId = $this->settings->getSPEntityId();
                if (!empty($validAudiences) && !isset($validAudiences[$spEntityId])) {
                    throw new ValidationError(
                        sprintf(
                            "Invalid audience for this Response (expected '%s', got '%s')",
                            $spEntityId,
                            implode(',', array_keys($validAudiences))
                        ),
                        ValidationError::WRONG_AUDIENCE
                    );
                }

                $idPEntityId = $this->settings->getIdPEntityId();

                // Check the issuers
                foreach (array_keys($this->getIssuers()) as $issuer) {
                    $trimmedIssuer = trim($issuer);
                    if (empty($trimmedIssuer) || $trimmedIssuer !== $idPEntityId) {
                        throw new ValidationError(
                            "Invalid issuer in the Assertion/Response (expected '$idPEntityId', got '$trimmedIssuer')",
                            ValidationError::WRONG_ISSUER
                        );
                    }
                }

                // Check the session Expiration
                $sessionExpiration = $this->getSessionNotOnOrAfter();
                $time = time();
                if ($sessionExpiration !== null && $sessionExpiration + self::ALLOWED_CLOCK_DRIFT <= $time) {
                    throw new ValidationError(
                        "The attributes have expired, based on the SessionNotOnOrAfter of the AttributeStatement of this Response",
                        ValidationError::SESSION_EXPIRED
                    );
                }

                // Check the SubjectConfirmation, at least one SubjectConfirmation must be valid
                $anySubjectConfirmation = false;
                /**
                 * @var DOMElement $scn
                 */
                foreach ($this->queryAssertion('/saml:Subject/saml:SubjectConfirmation') as $scn) {
                    if ($scn->hasAttribute('Method') && $scn->getAttribute('Method') !== Constants::CM_BEARER) {
                        continue;
                    }
                    $subjectConfirmationDataNodes = $scn->getElementsByTagName('SubjectConfirmationData');
                    if ($subjectConfirmationDataNodes->length === 0) {
                        continue;
                    }

                    $scnData = $subjectConfirmationDataNodes->item(0);
                    if (isset($responseInResponseTo) &&
                        $scnData->hasAttribute('InResponseTo') &&
                        $responseInResponseTo !== $scnData->getAttribute('InResponseTo')
                    ) {
                        continue;
                    }
                    if ($scnData->hasAttribute('Recipient')) {
                        $recipient = parse_url($scnData->getAttribute('Recipient'));
                        if (!empty($recipient) && ($recipient["host"] !== Utils::getSelfHost() || rtrim($recipient["path"], "/") !== rtrim(parse_url(Utils::getSelfRoutedURLNoQuery(), PHP_URL_PATH), "/"))) {
                            continue;
                        }
                    }
                    if ($scnData->hasAttribute('NotOnOrAfter')) {
                        $noa = Utils::parseSAML2Time($scnData->getAttribute('NotOnOrAfter'));
                        if ($noa + self::ALLOWED_CLOCK_DRIFT <= $time) {
                            continue;
                        }
                        $this->validSCDNotOnOrAfter = $noa;
                    }
                    if ($scnData->hasAttribute('NotBefore')) {
                        $nb = Utils::parseSAML2Time($scnData->getAttribute('NotBefore'));
                        if ($nb > $time + self::ALLOWED_CLOCK_DRIFT) {
                            continue;
                        }
                    }

                    $anySubjectConfirmation = true;
                    break;
                }

                if (!$anySubjectConfirmation) {
                    throw new ValidationError(
                        "A valid SubjectConfirmation was not found on this Response",
                        ValidationError::WRONG_SUBJECTCONFIRMATION
                    );
                }

                if (!$hasSignedAssertion && $this->settings->getSecurityWantAssertionsSigned()) {
                    throw new ValidationError(
                        "The Assertion of the Response is not signed and the SP requires it",
                        ValidationError::NO_SIGNED_ASSERTION
                    );
                }

                if (!$hasSignedResponse && $this->settings->getSecurityWantMessagesSigned()) {
                    throw new ValidationError(
                        "The Message of the Response is not signed and the SP requires it",
                        ValidationError::NO_SIGNED_MESSAGE
                    );
                }
            }

            // Detect case not supported
            if ($this->encrypted) {
                $encryptedIDNodes = Utils::query($this->decryptedDocument, '/samlp:Response/saml:Assertion/saml:Subject/saml:EncryptedID');
                if ($encryptedIDNodes->length > 0) {
                    throw new ValidationError(
                        'Unsigned SAML Response that contains a signed and encrypted Assertion with encrypted nameId is not supported.',
                        ValidationError::NOT_SUPPORTED
                    );
                }
            }

            if (empty($signedElements) || (!$hasSignedResponse && !$hasSignedAssertion)) {
                throw new ValidationError(
                    'No Signature found. SAML Response rejected',
                    ValidationError::NO_SIGNATURE_FOUND
                );
            }

            $cert = $this->settings->getIdPX509Certificate();
            $fingerprint = $this->settings->getIdPCertFingerprint();
            $fingerprintalg = $this->settings->getIdPCertFingerprintAlgorithm();
            $multiCerts = $this->settings->getIdPMultipleX509SigningCertificate();

            // If find a Signature on the Response, validates it checking the original response
            if ($hasSignedResponse &&
                !Utils::validateSign($this->document, $cert, $fingerprint, $fingerprintalg, self::RESPONSE_SIGNATURE_XPATH, $multiCerts)) {
                throw new ValidationError(
                    "Signature validation failed. SAML Response rejected",
                    ValidationError::INVALID_SIGNATURE
                );
            }

            // If find a Signature on the Assertion (decrypted assertion if was encrypted)
            if ($hasSignedAssertion &&
                !Utils::validateSign(
                    $this->encrypted ? $this->decryptedDocument : $this->document,
                    $cert,
                    $fingerprint,
                    $fingerprintalg,
                    self::ASSERTION_SIGNATURE_XPATH,
                    $multiCerts
                )
            ) {
                throw new ValidationError(
                    "Signature validation failed. SAML Response rejected",
                    ValidationError::INVALID_SIGNATURE
                );
            }

            return true;
        } catch (Exception $e) {
            $this->error = $e;
            return false;
        }
    }

    public function getId(): ?string
    {
        if ($this->document->documentElement->hasAttribute('ID')) {
            return $this->document->documentElement->getAttribute('ID');
        }
        return null;
    }

    /**
     * @throws ValidationError
     */
    public function getAssertionId(): ?string
    {
        if (!$this->validateNumAssertions()) {
            throw new ValidationError("SAML Response must contain 1 Assertion.", ValidationError::WRONG_NUMBER_OF_ASSERTIONS);
        }
        $assertionNodes = $this->queryAssertion("");

        if ($assertionNodes->length === 1) {
            $assertionNode = $assertionNodes->item(0);
            if ($assertionNode instanceof DOMElement && $assertionNode->hasAttribute('ID')) {
                return $assertionNode->getAttribute('ID');
            }
        }
        return null;
    }

    public function getAssertionNotOnOrAfter(): ?int
    {
        return $this->validSCDNotOnOrAfter;
    }

    /**
     * Checks if the Status is success
     *
     * @throws ValidationError If status is not success
     */
    public function checkStatus(): void
    {
        $status = Utils::getStatus($this->document);

        if (isset($status['code']) && $status['code'] !== Constants::STATUS_SUCCESS) {
            $explodedCode = explode(':', $status['code']);
            $statusExceptionMsg = 'The status code of the Response was not Success, was ' . array_pop($explodedCode);
            if (!empty($status['msg'])) {
                $statusExceptionMsg .= ' -> ' . $status['msg'];
            }
            throw new ValidationError(
                $statusExceptionMsg,
                ValidationError::STATUS_CODE_IS_NOT_SUCCESS
            );
        }
    }

    /**
     * Gets the Issuers (from Response and Assertion).
     *
     * @throws ValidationError
     */
    public function getIssuers(): array
    {
        $issuers = [];

        $responseIssuer = Utils::query($this->document, '/samlp:Response/saml:Issuer');
        if ($responseIssuer->length > 0) {
            if ($responseIssuer->length !== 1) {
                throw new ValidationError(
                    "Issuer of the Response is multiple.",
                    ValidationError::ISSUER_MULTIPLE_IN_RESPONSE
                );
            }
            $issuers[$responseIssuer->item(0)->textContent] = true;
        }

        $assertionIssuer = $this->queryAssertion('/saml:Issuer');
        if ($assertionIssuer->length !== 1) {
            throw new ValidationError(
                "Issuer of the Assertion not found or multiple.",
                ValidationError::ISSUER_NOT_FOUND_IN_ASSERTION
            );
        }
        $issuers[$assertionIssuer->item(0)->textContent] = true;

        return $issuers;
    }

    /**
     * Gets the NameID Data provided by the SAML response from the IdP.
     *
     * @return array{Value?:string,Format?:string,NameQualifier?:string,SPNameQualifier?:string}
     *
     * @throws ValidationError
     */
    public function getNameIdData(): array
    {
        $encryptedIdDataEntries = $this->queryAssertion('/saml:Subject/saml:EncryptedID/xenc:EncryptedData');

        if ($encryptedIdDataEntries->length === 1) {
            $seckey = new XMLSecurityKey(XMLSecurityKey::RSA_1_5, ['type' => 'private']);
            $seckey->loadKey($this->settings->getSPkey());

            $encryptedData = $encryptedIdDataEntries->item(0);
            assert($encryptedData instanceof DOMElement);
            $nameId = Utils::decryptElement($encryptedData, $seckey);
        } else {
            $entries = $this->queryAssertion('/saml:Subject/saml:NameID');
            if ($entries->length === 1) {
                $nameId = $entries->item(0);
            }
        }

        $nameIdData = [];

        if (!isset($nameId)) {
            if ($this->settings->getSecurityWantNameId()) {
                throw new ValidationError(
                    "NameID not found in the assertion of the Response",
                    ValidationError::NO_NAMEID
                );
            }
        } else {
            if ($this->settings->isStrict() && empty($nameId->nodeValue)) {
                throw new ValidationError(
                    "An empty NameID value found",
                    ValidationError::EMPTY_NAMEID
                );
            }
            $nameIdData['Value'] = $nameId->nodeValue;
            if ($nameId->hasAttribute("Format")) {
                $nameIdData["Format"] = $nameId->getAttribute("Format");
            }
            if ($nameId->hasAttribute("SPNameQualifier")) {
                $spNameQualifier = $nameId->getAttribute("SPNameQualifier");
                if ($this->settings->isStrict() && $this->settings->getSPEntityId() !== $spNameQualifier) {
                    throw new ValidationError(
                        "The SPNameQualifier value mismatch the SP entityID value.",
                        ValidationError::SP_NAME_QUALIFIER_NAME_MISMATCH
                    );
                }
                $nameIdData["SPNameQualifier"] = $spNameQualifier;
            }
            if ($nameId->hasAttribute("NameQualifier")) {
                $nameIdData["NameQualifier"] = $nameId->getAttribute("NameQualifier");
            }
        }

        return $nameIdData;
    }

    /**
     * Gets the NameID provided by the SAML response from the IdP.
     *
     * @throws ValidationError
     */
    public function getNameId(): ?string
    {
        $nameIdData = $this->getNameIdData();
        if (!empty($nameIdData) && isset($nameIdData['Value'])) {
            return $nameIdData['Value'];
        }
        return null;
    }

    /**
     * Gets the NameID Format provided by the SAML response from the IdP.
     *
     * @throws ValidationError
     */
    public function getNameIdFormat(): ?string
    {
        $nameIdData = $this->getNameIdData();
        if (!empty($nameIdData) && isset($nameIdData['Format'])) {
            return $nameIdData['Format'];
        }
        return null;
    }

    /**
     * Gets the NameID NameQualifier provided by the SAML response from the IdP.
     *
     * @throws ValidationError
     */
    public function getNameIdNameQualifier(): ?string
    {
        $nameIdData = $this->getNameIdData();
        if (!empty($nameIdData) && isset($nameIdData['NameQualifier'])) {
            return $nameIdData['NameQualifier'];
        }
        return null;
    }

    /**
     * Gets the NameID SP NameQualifier provided by the SAML response from the IdP.
     *
     * @throws ValidationError
     */
    public function getNameIdSPNameQualifier(): ?string
    {
        $nameIdData = $this->getNameIdData();
        if (!empty($nameIdData) && isset($nameIdData['SPNameQualifier'])) {
            return $nameIdData['SPNameQualifier'];
        }
        return null;
    }

    /**
     * Gets the SessionNotOnOrAfter from the AuthnStatement.
     * Could be used to set the local session expiration
     *
     * @throws Exception
     */
    public function getSessionNotOnOrAfter(): ?int
    {
        $entries = $this->queryAssertion('/saml:AuthnStatement[@SessionNotOnOrAfter]');
        if ($entries->length !== 0) {
            $entry = $entries->item(0);
            if ($entry instanceof DOMElement) {
                return Utils::parseSAML2Time($entry->getAttribute('SessionNotOnOrAfter'));
            }
        }
        return null;
    }

    /**
     * Gets the SessionIndex from the AuthnStatement.
     * Could be used to be stored in the local session in order
     * to be used in a future Logout Request that the SP could
     * send to the SP, to set what specific session must be deleted
     */
    public function getSessionIndex(): ?string
    {
        $entries = $this->queryAssertion('/saml:AuthnStatement[@SessionIndex]');
        if ($entries->length !== 0) {
            $entry = $entries->item(0);
            if ($entry instanceof DOMElement) {
                return $entry->getAttribute('SessionIndex');
            }
        }
        return null;
    }

    /**
     * Gets the Attributes from the AttributeStatement element.
     *
     * @throws ValidationError
     */
    public function getAttributes(): array
    {
        return $this->getAttributesByKeyName('Name');
    }

    /**
     * Gets the Attributes from the AttributeStatement element using their FriendlyName.
     *
     * @return array The attributes of the SAML Assertion
     *
     * @throws ValidationError
     */
    public function getAttributesWithFriendlyName(): array
    {
        return $this->getAttributesByKeyName('FriendlyName');
    }

    /**
     * @throws ValidationError
     */
    private function getAttributesByKeyName(string $keyName): array
    {
        $attributes = [];
        /** @var DOMNode $entry */
        foreach ($this->queryAssertion('/saml:AttributeStatement/saml:Attribute') as $entry) {
            $attributeKeyNode = $entry->attributes->getNamedItem($keyName);
            if ($attributeKeyNode === null) {
                continue;
            }
            $attributeKeyName = $attributeKeyNode->nodeValue;
            if (isset($attributes[$attributeKeyName])) {
                throw new ValidationError(
                    "Found an Attribute element with duplicated " . $keyName,
                    ValidationError::DUPLICATED_ATTRIBUTE_NAME_FOUND
                );
            }
            $attributeValues = [];
            foreach ($entry->childNodes as $childNode) {
                if ($childNode->nodeType === XML_ELEMENT_NODE &&
                    $childNode->tagName === (($childNode->prefix ? $childNode->prefix . ':' : '') . 'AttributeValue')
                ) {
                    $attributeValues[] = $childNode->nodeValue;
                }
            }
            $attributes[$attributeKeyName] = $attributeValues;
        }
        return $attributes;
    }

    /**
     * Verifies that the document only contains a single Assertion (encrypted or not).
     */
    private function validateNumAssertions(): bool
    {
        $valid = $this->document->getElementsByTagName('Assertion')->length +
            $this->document->getElementsByTagName('EncryptedAssertion')->length === 1;

        if ($this->encrypted) {
            return $valid && $this->decryptedDocument->getElementsByTagName('Assertion')->length === 1;
        }

        return $valid;
    }

    /**
     * Verifies the signature nodes:
     *   - Checks that are Response or Assertion
     *   - Check that IDs and reference URI are unique and consistent.
     *
     * @throws ValidationError
     */
    public function processSignedElements(): array
    {
        $signedElements = [];
        $verifiedSeis = [];
        $verifiedIds = [];

        /**
         * @var DOMElement $signNode
         */
        foreach ($this->encrypted ?
                $this->decryptedDocument->getElementsByTagName('Signature') :
                $this->document->getElementsByTagName('Signature') as $signNode) {
            $signedElement = '{' . $signNode->parentNode->namespaceURI . '}' . $signNode->parentNode->localName;

            if ($signedElement !== ('{' . Constants::NS_SAMLP . '}Response') && $signedElement !== ('{' . Constants::NS_SAML . '}Assertion')) {
                throw new ValidationError(
                    "Invalid Signature Element $signedElement SAML Response rejected",
                    ValidationError::WRONG_SIGNED_ELEMENT
                );
            }

            // Check that reference URI matches the parent ID and no duplicate References or IDs
            $idValue = $signNode->parentNode->getAttribute('ID');
            if (empty($idValue)) {
                throw new ValidationError(
                    'Signed Element must contain an ID. SAML Response rejected',
                    ValidationError::ID_NOT_FOUND_IN_SIGNED_ELEMENT
                );
            }

            if (isset($verifiedIds[$idValue])) {
                throw new ValidationError(
                    'Duplicated ID. SAML Response rejected',
                    ValidationError::DUPLICATED_ID_IN_SIGNED_ELEMENTS
                );
            }
            $verifiedIds[$idValue] = true;

            $ref = $signNode->getElementsByTagName('Reference');
            if ($ref->length !== 1) {
                throw new ValidationError(
                    'Unexpected number of Reference nodes found for signature. SAML Response rejected.',
                    ValidationError::UNEXPECTED_REFERENCE
                );
            }

            $sei = $ref->item(0)->getAttribute('URI');
            if (!empty($sei)) {
                $sei = substr($sei, 1);

                if ($sei !== $idValue) {
                    throw new ValidationError(
                        'Found an invalid Signed Element. SAML Response rejected',
                        ValidationError::INVALID_SIGNED_ELEMENT
                    );
                }

                if (isset($verifiedSeis[$sei])) {
                    throw new ValidationError(
                        'Duplicated Reference URI. SAML Response rejected',
                        ValidationError::DUPLICATED_REFERENCE_IN_SIGNED_ELEMENTS
                    );
                }
                $verifiedSeis[$sei] = true;
            }
            $signedElements[] = $signedElement;
        }

        // Check SignedElements
        if (!empty($signedElements) && !$this->validateSignedElements($signedElements)) {
            throw new ValidationError(
                'Found an unexpected Signature Element. SAML Response rejected',
                ValidationError::UNEXPECTED_SIGNED_ELEMENTS
            );
        }
        return $signedElements;
    }

    /**
     * Verifies that the document is still valid according Conditions Element.
     *
     * @throws Exception
     * @throws ValidationError
     */
    public function validateTimestamps(): void
    {
        $timestampNodes = ($this->encrypted ? $this->decryptedDocument : $this->document)->getElementsByTagName('Conditions');
        $time = time();
        for ($i = 0; $i < $timestampNodes->length; ++$i) {
            $attributes = $timestampNodes->item($i)->attributes;
            $attribute = $attributes->getNamedItem("NotBefore");
            if ($attribute instanceof DOMNode && Utils::parseSAML2Time($attribute->textContent) > $time + self::ALLOWED_CLOCK_DRIFT) {
                throw new ValidationError(
                    'Could not validate timestamp: not yet valid. Check system clock.',
                    ValidationError::ASSERTION_TOO_EARLY
                );
            }
            $attribute = $attributes->getNamedItem("NotOnOrAfter");
            if ($attribute instanceof DOMNode && Utils::parseSAML2Time($attribute->textContent) + self::ALLOWED_CLOCK_DRIFT <= $time) {
                throw new ValidationError(
                    'Could not validate timestamp: expired. Check system clock.',
                    ValidationError::ASSERTION_EXPIRED
                );
            }
        }
    }

    /**
     * Verifies that the document has the expected signed nodes.
     *
     * @throws ValidationError
     */
    private function validateSignedElements(array $signedElements): bool
    {
        if (count($signedElements) > 2) {
            return false;
        }

        $responseTag = '{' . Constants::NS_SAMLP . '}Response';
        $assertionTag = '{' . Constants::NS_SAML . '}Assertion';

        $occurrence = array_count_values($signedElements);
        if ((in_array($responseTag, $signedElements) && $occurrence[$responseTag] > 1)
            || (in_array($assertionTag, $signedElements) && $occurrence[$assertionTag] > 1)
            || (!in_array($responseTag, $signedElements) && !in_array($assertionTag, $signedElements))
        ) {
            return false;
        }

        // Check that the signed elements found here, are the ones that will be verified
        // by Utils->validateSign()
        if (in_array($responseTag, $signedElements) && Utils::query($this->document, self::RESPONSE_SIGNATURE_XPATH)->length !== 1) {
            throw new ValidationError(
                "Unexpected number of Response signatures found. SAML Response rejected.",
                ValidationError::WRONG_NUMBER_OF_SIGNATURES_IN_RESPONSE
            );
        }

        if (in_array($assertionTag, $signedElements) &&
            Utils::query($this->encrypted ? $this->decryptedDocument : $this->document, self::ASSERTION_SIGNATURE_XPATH)->length !== 1
        ) {
            throw new ValidationError(
                "Unexpected number of Assertion signatures found. SAML Response rejected.",
                ValidationError::WRONG_NUMBER_OF_SIGNATURES_IN_ASSERTION
            );
        }

        return true;
    }

    /**
     * Extracts a node from the DOMDocument (Assertion).
     */
    private function queryAssertion(string $assertionXpath): DOMNodeList
    {
        $xpath = new DOMXPath($this->encrypted ? $this->decryptedDocument : $this->document);

        $xpath->registerNamespace('samlp', Constants::NS_SAMLP);
        $xpath->registerNamespace('saml', Constants::NS_SAML);
        $xpath->registerNamespace('ds', Constants::NS_DS);
        $xpath->registerNamespace('xenc', Constants::NS_XENC);

        $assertionNode = '/samlp:Response/saml:Assertion';
        $assertionReferenceNode = $xpath->query($assertionNode . '/ds:Signature/ds:SignedInfo/ds:Reference')->item(0);
        if (!$assertionReferenceNode) {
            // is the response signed as a whole?
            $responseReferenceNode = $xpath->query('/samlp:Response/ds:Signature/ds:SignedInfo/ds:Reference')->item(0);
            if ($responseReferenceNode) {
                $uri = $responseReferenceNode->attributes->getNamedItem('URI')->nodeValue;
                $id = empty($uri) ?
                    $responseReferenceNode->parentNode->parentNode->parentNode->attributes->getNamedItem('ID')->nodeValue :
                    substr($uri, 1);
                $nameQuery = "/samlp:Response[@ID='$id']/saml:Assertion" . $assertionXpath;
            } else {
                $nameQuery = "/samlp:Response/saml:Assertion" . $assertionXpath;
            }
        } else {
            $uri = $assertionReferenceNode->attributes->getNamedItem('URI')->nodeValue;
            $id = empty($uri) ?
                $assertionReferenceNode->parentNode->parentNode->parentNode->attributes->getNamedItem('ID')->nodeValue :
                substr($uri, 1);
            $nameQuery = $assertionNode . "[@ID='$id']" . $assertionXpath;
        }

        return $xpath->query($nameQuery);
    }

    /**
     * Decrypts the Assertion (DOMDocument)
     *
     * @throws Exception
     * @throws ValidationError
     */
    private function decryptAssertion(DOMDocument $dom): DOMDocument
    {
        $pem = $this->settings->getSPkey();

        if (empty($pem)) {
            throw new Error(
                "No private key available, check settings",
                Error::PRIVATE_KEY_NOT_FOUND
            );
        }

        $objenc = new XMLSecEnc();
        $encData = $objenc->locateEncryptedData($dom);
        if (!$encData instanceof DOMElement) {
            throw new ValidationError(
                "Cannot locate encrypted assertion",
                ValidationError::MISSING_ENCRYPTED_ELEMENT
            );
        }

        $objenc->setNode($encData);
        $objenc->type = $encData->getAttribute("Type");
        $objKey = $objenc->locateKey();
        if (!$objKey instanceof XMLSecurityKey) {
            throw new ValidationError(
                "Unknown algorithm",
                ValidationError::KEY_ALGORITHM_ERROR
            );
        }

        $objKeyInfo = $objenc->locateKeyInfo($objKey);
        if ($objKeyInfo instanceof XMLSecurityKey) {
            $objKeyInfo->loadKey($pem);
            if ($objKeyInfo->isEncrypted) {
                $encryptedContext = $objKeyInfo->encryptedCtx;
                if ($encryptedContext instanceof XMLSecEnc && empty($objKey->key)) {
                    $key = $encryptedContext->decryptKey($objKeyInfo);
                    if (is_string($key)) {
                        $objKey->loadKey($key);
                    }
                }
            }
        }

        $decrypted = new DOMDocument();
        try {
            $xml = $objenc->decryptNode($objKey, false);
            if (!is_string($xml)) {
                throw new Exception("Assertion decryption failed");
            }
            Utils::loadXML($decrypted, $xml);
        } catch (Exception $e) {
            throw new Exception('Error: string from decrypted assertion could not be loaded into a XML document');
        }
        if ($encData->parentNode instanceof DOMDocument) {
            return $decrypted;
        }

        $decrypted = $decrypted->documentElement;
        $encryptedAssertion = $encData->parentNode;
        assert($encryptedAssertion instanceof DOMElement);
        $container = $encryptedAssertion->parentNode;
        assert($container instanceof DOMElement);

        // Fix possible issue with saml namespace
        if (!$decrypted->hasAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:saml')
            && !$decrypted->hasAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:saml2')
            && !$decrypted->hasAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns')
            && !$container->hasAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:saml')
            && !$container->hasAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:saml2')
        ) {
            if (strpos($encryptedAssertion->tagName, 'saml2:') !== false) {
                $ns = 'xmlns:saml2';
            } elseif (strpos($encryptedAssertion->tagName, 'saml:') !== false) {
                $ns = 'xmlns:saml';
            } else {
                $ns = 'xmlns';
            }
            $decrypted->setAttributeNS('http://www.w3.org/2000/xmlns/', $ns, Constants::NS_SAML);
        }

        Utils::treeCopyReplace($encryptedAssertion, $decrypted);

        // Rebuild the DOM will fix issues with namespaces as well
        Utils::loadXML($newDom = new DOMDocument(), $container->ownerDocument->saveXML());
        return $newDom;
    }

    /**
     * After execute a validation process, if fails this method returns the cause
     */
    public function getErrorException(): Exception
    {
        return $this->error;
    }
}
