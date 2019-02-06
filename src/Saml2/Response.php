<?php
namespace OneLogin\Saml2;

use DOMDocument;
use DOMElement;
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
     * @var int
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
     *
     * @param string|null $requestId The ID of the AuthNRequest sent by this SP to the IdP
     *
     * @return bool Validate the document
     *
     * @throws Exception
     * @throws ValidationError
     */
    public function isValid($requestId = null)
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

            $idpData = $this->settings->getIdPData();
            $idPEntityId = $idpData['entityId'];
            $spData = $this->settings->getSPData();
            $spEntityId = $spData['entityId'];

            $signedElements = $this->processSignedElements();

            $hasSignedResponse = in_array('{' . Constants::NS_SAMLP . '}Response', $signedElements);
            $hasSignedAssertion = in_array('{' . Constants::NS_SAML . '}Assertion', $signedElements);

            if ($this->settings->isStrict()) {
                $security = $this->settings->getSecurityData();

                if ($security['wantXMLValidation']) {
                    $errorXmlMsg = "Invalid SAML Response. Not match the saml-schema-protocol-2.0.xsd";
                    $res = Utils::validateXML($this->document, 'saml-schema-protocol-2.0.xsd');
                    if (!$res instanceof DOMDocument) {
                        throw new ValidationError(
                            $errorXmlMsg,
                            ValidationError::INVALID_XML_FORMAT
                        );
                    }

                    // If encrypted, check also the decrypted document
                    if ($this->encrypted) {
                        $res = Utils::validateXML($this->decryptedDocument, 'saml-schema-protocol-2.0.xsd');
                        if (!$res instanceof DOMDocument) {
                            throw new ValidationError(
                                $errorXmlMsg,
                                ValidationError::INVALID_XML_FORMAT
                            );
                        }
                    }
                }

                $currentURL = Utils::getSelfRoutedURLNoQuery();

                if ($this->document->documentElement->hasAttribute('InResponseTo')) {
                    $responseInResponseTo = $this->document->documentElement->getAttribute('InResponseTo');
                }

                // Check if the InResponseTo of the Response matchs the ID of the AuthNRequest (requestId) if provided
                if (isset($requestId) && isset($responseInResponseTo) && $requestId !== $responseInResponseTo) {
                    throw new ValidationError(
                        "The InResponseTo of the Response: $responseInResponseTo, does not match the ID of the AuthNRequest sent by the SP: $requestId",
                        ValidationError::WRONG_INRESPONSETO
                    );
                }

                if (!$this->encrypted && $security['wantAssertionsEncrypted']) {
                    throw new ValidationError(
                        "The assertion of the Response is not encrypted and the SP requires it",
                        ValidationError::NO_ENCRYPTED_ASSERTION
                    );
                }

                if ($security['wantNameIdEncrypted']) {
                    if ($this->queryAssertion('/saml:Subject/saml:EncryptedID/xenc:EncryptedData')->length !== 1) {
                        throw new ValidationError(
                            "The NameID of the Response is not encrypted and the SP requires it",
                            ValidationError::NO_ENCRYPTED_NAMEID
                        );
                    }
                }

                // Validate Conditions element exists
                if (!$this->checkOneCondition()) {
                    throw new ValidationError(
                        "The Assertion must include a Conditions element",
                        ValidationError::MISSING_CONDITIONS
                    );
                }

                // Validate Asserion timestamps
                $this->validateTimestamps();

                // Validate AuthnStatement element exists and is unique
                if (!$this->checkOneAuthnStatement()) {
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
                        if (!$security['relaxDestinationValidation']) {
                            throw new ValidationError(
                                "The response has an empty Destination value",
                                ValidationError::EMPTY_DESTINATION
                            );
                        }
                    } else {
                        if (strpos($destination, $currentURL) !== 0) {
                            if (strpos($destination, Utils::getSelfURLNoQuery()) !== 0) {
                                throw new ValidationError(
                                    "The response was received at $currentURL instead of $destination",
                                    ValidationError::WRONG_DESTINATION
                                );
                            }
                        }
                    }
                }

                // Check audience
                $validAudiences = $this->getAudiences();
                if (!empty($validAudiences) && !in_array($spEntityId, $validAudiences, true)) {
                    throw new ValidationError(
                        sprintf(
                            "Invalid audience for this Response (expected '%s', got '%s')",
                            $spEntityId,
                            implode(',', $validAudiences)
                        ),
                        ValidationError::WRONG_AUDIENCE
                    );
                }

                // Check the issuers
                foreach ($this->getIssuers() as $issuer) {
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
                if (!empty($sessionExpiration) && $sessionExpiration + Constants::ALLOWED_CLOCK_DRIFT <= time()) {
                    throw new ValidationError(
                        "The attributes have expired, based on the SessionNotOnOrAfter of the AttributeStatement of this Response",
                        ValidationError::SESSION_EXPIRED
                    );
                }

                // Check the SubjectConfirmation, at least one SubjectConfirmation must be valid
                $anySubjectConfirmation = false;
                foreach ($this->queryAssertion('/saml:Subject/saml:SubjectConfirmation') as $scn) {
                    if ($scn->hasAttribute('Method') && $scn->getAttribute('Method') !== Constants::CM_BEARER) {
                        continue;
                    }
                    $subjectConfirmationDataNodes = $scn->getElementsByTagName('SubjectConfirmationData');
                    if ($subjectConfirmationDataNodes->length === 0) {
                        continue;
                    } else {
                        $scnData = $subjectConfirmationDataNodes->item(0);
                        if ($scnData->hasAttribute('InResponseTo')) {
                            if (isset($responseInResponseTo) && $responseInResponseTo !== $scnData->getAttribute('InResponseTo')) {
                                continue;
                            }
                        }
                        if ($scnData->hasAttribute('Recipient')) {
                            $recipient = $scnData->getAttribute('Recipient');
                            if (!empty($recipient) && strpos($recipient, $currentURL) === false) {
                                continue;
                            }
                        }
                        if ($scnData->hasAttribute('NotOnOrAfter')) {
                            $noa = Utils::parseSAML2Time($scnData->getAttribute('NotOnOrAfter'));
                            if ($noa + Constants::ALLOWED_CLOCK_DRIFT <= time()) {
                                continue;
                            }
                        }
                        if ($scnData->hasAttribute('NotBefore')) {
                            $nb = Utils::parseSAML2Time($scnData->getAttribute('NotBefore'));
                            if ($nb > time() + Constants::ALLOWED_CLOCK_DRIFT) {
                                continue;
                            }
                        }

                        // Save NotOnOrAfter value
                        if ($scnData->hasAttribute('NotOnOrAfter')) {
                            $this->validSCDNotOnOrAfter = $noa;
                        }
                        $anySubjectConfirmation = true;
                        break;
                    }
                }

                if (!$anySubjectConfirmation) {
                    throw new ValidationError(
                        "A valid SubjectConfirmation was not found on this Response",
                        ValidationError::WRONG_SUBJECTCONFIRMATION
                    );
                }

                if ($security['wantAssertionsSigned'] && !$hasSignedAssertion) {
                    throw new ValidationError(
                        "The Assertion of the Response is not signed and the SP requires it",
                        ValidationError::NO_SIGNED_ASSERTION
                    );
                }

                if ($security['wantMessagesSigned'] && !$hasSignedResponse) {
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
            } else {
                $cert = $idpData['x509cert'];
                $fingerprint = $idpData['certFingerprint'];
                $fingerprintalg = $idpData['certFingerprintAlgorithm'];

                $multiCerts = null;
                if (isset($idpData['x509certMulti']) && isset($idpData['x509certMulti']['signing']) && !empty($idpData['x509certMulti']['signing'])) {
                    $multiCerts = $idpData['x509certMulti']['signing'];
                }

                // If find a Signature on the Response, validates it checking the original response
                if ($hasSignedResponse && !Utils::validateSign($this->document, $cert, $fingerprint, $fingerprintalg, Utils::RESPONSE_SIGNATURE_XPATH, $multiCerts)) {
                    throw new ValidationError(
                        "Signature validation failed. SAML Response rejected",
                        ValidationError::INVALID_SIGNATURE
                    );
                }

                // If find a Signature on the Assertion (decrypted assertion if was encrypted)
                $documentToCheckAssertion = $this->encrypted ? $this->decryptedDocument : $this->document;
                if ($hasSignedAssertion && !Utils::validateSign($documentToCheckAssertion, $cert, $fingerprint, $fingerprintalg, Utils::ASSERTION_SIGNATURE_XPATH, $multiCerts)) {
                    throw new ValidationError(
                        "Signature validation failed. SAML Response rejected",
                        ValidationError::INVALID_SIGNATURE
                    );
                }
            }
            return true;
        } catch (Exception $e) {
            $this->error = $e;
            return false;
        }
    }

    /**
     * @return string|null the ID of the Response
     */
    public function getId()
    {
        if ($this->document->documentElement->hasAttribute('ID')) {
            return $this->document->documentElement->getAttribute('ID');
        }
        return null;
    }

    /**
     * @return string|null the ID of the assertion in the Response
     *
     * @throws ValidationError
     */
    public function getAssertionId()
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

    /**
     * @return int the NotOnOrAfter value of the valid SubjectConfirmationData
     * node if any
     */
    public function getAssertionNotOnOrAfter()
    {
        return $this->validSCDNotOnOrAfter;
    }

    /**
     * Checks if the Status is success
     *
     * @throws ValidationError If status is not success
     */
    public function checkStatus()
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
     * Checks that the samlp:Response/saml:Assertion/saml:Conditions element exists and is unique.
     *
     * @return bool true if the Conditions element exists and is unique
     */
    public function checkOneCondition()
    {
        return $this->queryAssertion("/saml:Conditions")->length === 1;
    }

    /**
     * Checks that the samlp:Response/saml:Assertion/saml:AuthnStatement element exists and is unique.
     *
     * @return bool true if the AuthnStatement element exists and is unique
     */
    public function checkOneAuthnStatement()
    {
        return $this->queryAssertion("/saml:AuthnStatement")->length === 1;
    }

    public function getAudiences(): array
    {
        $audiences = [];

        foreach ($this->queryAssertion('/saml:Conditions/saml:AudienceRestriction/saml:Audience') as $entry) {
            $value = trim($entry->textContent);
            if (!empty($value)) {
                $audiences[] = $value;
            }
        }

        return array_unique($audiences);
    }

    /**
     * Gets the Issuers (from Response and Assertion).
     *
     * @return array @issuers The issuers of the assertion/response
     *
     * @throws ValidationError
     */
    public function getIssuers()
    {
        $issuers = [];

        $responseIssuer = Utils::query($this->document, '/samlp:Response/saml:Issuer');
        if ($responseIssuer->length > 0) {
            if ($responseIssuer->length === 1) {
                $issuers[] = $responseIssuer->item(0)->textContent;
            } else {
                throw new ValidationError(
                    "Issuer of the Response is multiple.",
                    ValidationError::ISSUER_MULTIPLE_IN_RESPONSE
                );
            }
        }

        $assertionIssuer = $this->queryAssertion('/saml:Issuer');
        if ($assertionIssuer->length === 1) {
            $issuers[] = $assertionIssuer->item(0)->textContent;
        } else {
            throw new ValidationError(
                "Issuer of the Assertion not found or multiple.",
                ValidationError::ISSUER_NOT_FOUND_IN_ASSERTION
            );
        }

        return array_unique($issuers);
    }

    /**
     * Gets the NameID Data provided by the SAML response from the IdP.
     *
     * @return array Name ID Data (Value, Format, NameQualifier, SPNameQualifier)
     *
     * @throws ValidationError
     */
    public function getNameIdData()
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
            $security = $this->settings->getSecurityData();
            if ($security['wantNameId']) {
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

            foreach (['Format', 'SPNameQualifier', 'NameQualifier'] as $attr) {
                if ($nameId->hasAttribute($attr)) {
                    if ($this->settings->isStrict() && $attr === 'SPNameQualifier') {
                        $spData = $this->settings->getSPData();
                        if ($spData['entityId'] !== $nameId->getAttribute($attr)) {
                            throw new ValidationError(
                                "The SPNameQualifier value mistmatch the SP entityID value.",
                                ValidationError::SP_NAME_QUALIFIER_NAME_MISMATCH
                            );
                        }
                    }
                    $nameIdData[$attr] = $nameId->getAttribute($attr);
                }
            }
        }

        return $nameIdData;
    }

    /**
     * Gets the NameID provided by the SAML response from the IdP.
     *
     * @return string|null Name ID Value
     *
     * @throws ValidationError
     */
    public function getNameId()
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
     * @return string|null Name ID Format
     *
     * @throws ValidationError
     */
    public function getNameIdFormat()
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
     * @return string|null Name ID NameQualifier
     *
     * @throws ValidationError
     */
    public function getNameIdNameQualifier()
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
     * @return string|null NameID SP NameQualifier
     *
     * @throws ValidationError
     */
    public function getNameIdSPNameQualifier()
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
     * @return int|null The SessionNotOnOrAfter value
     *
     * @throws Exception
     */
    public function getSessionNotOnOrAfter()
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
     *
     * @return string|null The SessionIndex value
     */
    public function getSessionIndex()
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
     * @return array The attributes of the SAML Assertion
     *
     * @throws ValidationError
     */
    public function getAttributes()
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
    public function getAttributesWithFriendlyName()
    {
        return $this->getAttributesByKeyName('FriendlyName');
    }

    /**
     * @param string $keyName
     *
     * @return array
     *
     * @throws ValidationError
     */
    private function getAttributesByKeyName($keyName = "Name"): array
    {
        $attributes = [];
        $entries = $this->queryAssertion('/saml:AttributeStatement/saml:Attribute');
        /** @var DOMNode $entry */
        foreach ($entries as $entry) {
            $attributeKeyNode = $entry->attributes->getNamedItem($keyName);
            if ($attributeKeyNode === null) {
                continue;
            }
            $attributeKeyName = $attributeKeyNode->nodeValue;
            if (in_array($attributeKeyName, array_keys($attributes))) {
                throw new ValidationError(
                    "Found an Attribute element with duplicated " . $keyName,
                    ValidationError::DUPLICATED_ATTRIBUTE_NAME_FOUND
                );
            }
            $attributeValues = [];
            foreach ($entry->childNodes as $childNode) {
                $tagName = ($childNode->prefix ? $childNode->prefix . ':' : '') . 'AttributeValue';
                if ($childNode->nodeType === XML_ELEMENT_NODE && $childNode->tagName === $tagName) {
                    $attributeValues[] = $childNode->nodeValue;
                }
            }
            $attributes[$attributeKeyName] = $attributeValues;
        }
        return $attributes;
    }

    /**
     * Verifies that the document only contains a single Assertion (encrypted or not).
     *
     * @return bool TRUE if the document passes.
     */
    public function validateNumAssertions()
    {
        $valid = $this->document->getElementsByTagName('Assertion')->length + $this->document->getElementsByTagName('EncryptedAssertion')->length === 1;

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
     * @return array Signed element tags
     *
     * @throws ValidationError
     */
    public function processSignedElements()
    {
        $signedElements = [];
        $verifiedSeis = [];
        $verifiedIds = [];

        if ($this->encrypted) {
            $signNodes = $this->decryptedDocument->getElementsByTagName('Signature');
        } else {
            $signNodes = $this->document->getElementsByTagName('Signature');
        }
        foreach ($signNodes as $signNode) {
            $responseTag = '{' . Constants::NS_SAMLP . '}Response';
            $assertionTag = '{' . Constants::NS_SAML . '}Assertion';

            $signedElement = '{' . $signNode->parentNode->namespaceURI . '}' . $signNode->parentNode->localName;

            if ($signedElement !== $responseTag && $signedElement !== $assertionTag) {
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

            if (in_array($idValue, $verifiedIds)) {
                throw new ValidationError(
                    'Duplicated ID. SAML Response rejected',
                    ValidationError::DUPLICATED_ID_IN_SIGNED_ELEMENTS
                );
            }
            $verifiedIds[] = $idValue;

            $ref = $signNode->getElementsByTagName('Reference');
            if ($ref->length === 1) {
                $ref = $ref->item(0);
                $sei = $ref->getAttribute('URI');
                if (!empty($sei)) {
                    $sei = substr($sei, 1);

                    if ($sei !== $idValue) {
                        throw new ValidationError(
                            'Found an invalid Signed Element. SAML Response rejected',
                            ValidationError::INVALID_SIGNED_ELEMENT
                        );
                    }

                    if (in_array($sei, $verifiedSeis)) {
                        throw new ValidationError(
                            'Duplicated Reference URI. SAML Response rejected',
                            ValidationError::DUPLICATED_REFERENCE_IN_SIGNED_ELEMENTS
                        );
                    }
                    $verifiedSeis[] = $sei;
                }
            } else {
                throw new ValidationError(
                    'Unexpected number of Reference nodes found for signature. SAML Response rejected.',
                    ValidationError::UNEXPECTED_REFERENCE
                );
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
     * @return bool
     *
     * @throws Exception
     * @throws ValidationError
     */
    public function validateTimestamps()
    {
        if ($this->encrypted) {
            $document = $this->decryptedDocument;
        } else {
            $document = $this->document;
        }

        $timestampNodes = $document->getElementsByTagName('Conditions');
        for ($i = 0; $i < $timestampNodes->length; $i++) {
            $nbAttribute = $timestampNodes->item($i)->attributes->getNamedItem("NotBefore");
            $naAttribute = $timestampNodes->item($i)->attributes->getNamedItem("NotOnOrAfter");
            if ($nbAttribute && Utils::parseSAML2Time($nbAttribute->textContent) > time() + Constants::ALLOWED_CLOCK_DRIFT) {
                throw new ValidationError(
                    'Could not validate timestamp: not yet valid. Check system clock.',
                    ValidationError::ASSERTION_TOO_EARLY
                );
            }
            if ($naAttribute && Utils::parseSAML2Time($naAttribute->textContent) + Constants::ALLOWED_CLOCK_DRIFT <= time()) {
                throw new ValidationError(
                    'Could not validate timestamp: expired. Check system clock.',
                    ValidationError::ASSERTION_EXPIRED
                );
            }
        }
        return true;
    }

    /**
     * Verifies that the document has the expected signed nodes.
     *
     * @param array $signedElements Signed elements
     *
     * @return bool
     *
     * @throws ValidationError
     */
    public function validateSignedElements($signedElements)
    {
        if (count($signedElements) > 2) {
            return false;
        }

        $responseTag = '{' . Constants::NS_SAMLP . '}Response';
        $assertionTag = '{' . Constants::NS_SAML . '}Assertion';

        $ocurrence = array_count_values($signedElements);
        if ((in_array($responseTag, $signedElements) && $ocurrence[$responseTag] > 1)
            || (in_array($assertionTag, $signedElements) && $ocurrence[$assertionTag] > 1)
            || !in_array($responseTag, $signedElements) && !in_array($assertionTag, $signedElements)
        ) {
            return false;
        }

        // Check that the signed elements found here, are the ones that will be verified
        // by Utils->validateSign()
        if (in_array($responseTag, $signedElements)) {
            $expectedSignatureNodes = Utils::query($this->document, Utils::RESPONSE_SIGNATURE_XPATH);
            if ($expectedSignatureNodes->length !== 1) {
                throw new ValidationError(
                    "Unexpected number of Response signatures found. SAML Response rejected.",
                    ValidationError::WRONG_NUMBER_OF_SIGNATURES_IN_RESPONSE
                );
            }
        }

        if (in_array($assertionTag, $signedElements)) {
            $expectedSignatureNodes = $this->query(Utils::ASSERTION_SIGNATURE_XPATH);
            if ($expectedSignatureNodes->length !== 1) {
                throw new ValidationError(
                    "Unexpected number of Assertion signatures found. SAML Response rejected.",
                    ValidationError::WRONG_NUMBER_OF_SIGNATURES_IN_ASSERTION
                );
            }
        }

        return true;
    }

    /**
     * Extracts a node from the DOMDocument (Assertion).
     *
     * @param string $assertionXpath Xpath Expression
     *
     * @return DOMNodeList The queried node
     */
    protected function queryAssertion($assertionXpath)
    {
        if ($this->encrypted) {
            $xpath = new DOMXPath($this->decryptedDocument);
        } else {
            $xpath = new DOMXPath($this->document);
        }

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
                if (empty($uri)) {
                    $id = $responseReferenceNode->parentNode->parentNode->parentNode->attributes->getNamedItem('ID')->nodeValue;
                } else {
                    $id = substr($responseReferenceNode->attributes->getNamedItem('URI')->nodeValue, 1);
                }
                $nameQuery = "/samlp:Response[@ID='$id']/saml:Assertion" . $assertionXpath;
            } else {
                $nameQuery = "/samlp:Response/saml:Assertion" . $assertionXpath;
            }
        } else {
            $uri = $assertionReferenceNode->attributes->getNamedItem('URI')->nodeValue;
            if (empty($uri)) {
                $id = $assertionReferenceNode->parentNode->parentNode->parentNode->attributes->getNamedItem('ID')->nodeValue;
            } else {
                $id = substr($assertionReferenceNode->attributes->getNamedItem('URI')->nodeValue, 1);
            }
            $nameQuery = $assertionNode . "[@ID='$id']" . $assertionXpath;
        }

        return $xpath->query($nameQuery);
    }

    /**
     * Extracts nodes that match the query from the DOMDocument (Response Menssage)
     *
     * @param string $query Xpath Expression
     *
     * @return DOMNodeList The queried nodes
     */
    private function query($query)
    {
        return Utils::query($this->encrypted ? $this->decryptedDocument : $this->document, $query);
    }

    /**
     * Decrypts the Assertion (DOMDocument)
     *
     * @param \DomNode $dom DomDocument
     *
     * @throws Exception
     * @throws ValidationError
     */
    protected function decryptAssertion(\DomNode $dom): DOMDocument
    {
        $pem = $this->settings->getSPkey();

        if (empty($pem)) {
            throw new Error(
                "No private key available, check settings",
                Error::PRIVATE_KEY_NOT_FOUND
            );
        }

        $objenc = new XMLSecEnc();
        if (!$dom instanceof DOMDocument) {
            $dom = $dom->ownerDocument;
        }
        $encData = $objenc->locateEncryptedData($dom);
        if (!$encData instanceof DOMElement) {
            throw new ValidationError(
                "Cannot locate encrypted assertion",
                ValidationError::MISSING_ENCRYPTED_ELEMENT
            );
        }

        $objenc->setNode($encData);
        $objenc->type = $encData->getAttribute("Type");
        if (!$objKey = $objenc->locateKey()) {
            throw new ValidationError(
                "Unknown algorithm",
                ValidationError::KEY_ALGORITHM_ERROR
            );
        }

        $key = null;
        if ($objKeyInfo = $objenc->locateKeyInfo($objKey)) {
            if ($objKeyInfo->isEncrypted) {
                $objKeyInfo->loadKey($pem, false, false);
                $key = $objKeyInfo->encryptedCtx->decryptKey($objKeyInfo);
            } else {
                // symmetric encryption key support
                $objKeyInfo->loadKey($pem, false, false);
            }
        }

        if (empty($objKey->key)) {
            $objKey->loadKey($key);
        }

        $decrypted = new DOMDocument();
        try {
            Utils::loadXML($decrypted, $objenc->decryptNode($objKey, false));
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
