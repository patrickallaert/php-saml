<?php
namespace OneLogin\Saml2;

use DOMDocument;
use Exception;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

class Settings
{
    /**
     * List of paths.
     *
     * @var array
     */
    private $paths = [];

    /**
     * @var string
     */
    private $baseurl;

    /**
     * Strict. If active, PHP Toolkit will reject unsigned or unencrypted messages
     * if it expects them signed or encrypted. If not, the messages will be accepted
     * and some security issues will be also relaxed.
     *
     * @var bool
     */
    private $strict = false;

    /**
     * SP data.
     *
     * @var array
     */
    private $sp = [];

    /**
     * IdP data.
     *
     * @var array
     */
    private $idp = [];

    /**
     * Compression settings that determine
     * whether gzip compression should be used.
     *
     * @var array
     */
    private $compress = [];

    /**
     * Security Info related to the SP.
     *
     * @var array
     */
    private $security = [];

    /**
     * Setting contacts.
     *
     * @var array
     */
    private $contacts = [];

    /**
     * Setting organization.
     *
     * @var array
     */
    private $organization = [];

    /**
     * Setting errors.
     *
     * @var array
     */
    private $errors = [];

    /**
     * Valitate SP data only flag
     *
     * @var bool
     */
    private $spValidationOnly = false;

    /**
     * Initializes the settings:
     * - Sets the paths of the different folders
     * - Loads settings info from settings file or array/object provided
     *
     * @param array|null $settings         SAML Toolkit Settings
     * @param bool       $spValidationOnly Validate or not the IdP data
     *
     * @throws Error If any settings parameter is invalid
     * @throws Exception If Settings is incorrectly supplied
     */
    public function __construct(array $settings = null, $spValidationOnly = false)
    {
        $this->spValidationOnly = $spValidationOnly;
        $this->loadPaths();

        if (!isset($settings)) {
            if (!$this->loadSettingsFromFile()) {
                throw new Error(
                    'Invalid file settings: %s',
                    Error::SETTINGS_INVALID,
                    [implode(', ', $this->errors)]
                );
            }
            $this->addDefaultValues();
        } else {
            if (!$this->loadSettingsFromArray($settings)) {
                throw new Error(
                    'Invalid array settings: %s',
                    Error::SETTINGS_INVALID,
                    [implode(', ', $this->errors)]
                );
            }
        }

        $this->formatIdPCert();
        $this->formatSPCert();
        $this->formatSPKey();
        $this->formatSPCertNew();
        $this->formatIdPCertMulti();
    }

    /**
     * Sets the paths of the different folders
     * @suppress PhanUndeclaredConstant
     */
    private function loadPaths()
    {
        $basePath = dirname(dirname(__DIR__)) . '/';
        $this->paths = [
            'base' => $basePath,
            'config' => $basePath,
            'cert' => $basePath . 'certs/',
            'lib' => $basePath . 'src/',
        ];

        if (defined('ONELOGIN_CUSTOMPATH')) {
            $this->paths['config'] = ONELOGIN_CUSTOMPATH;
            $this->paths['cert'] = ONELOGIN_CUSTOMPATH . 'certs/';
        }
    }

    public function getBasePath(): string
    {
        return $this->paths['base'];
    }

    public function getCertPath(): string
    {
        return $this->paths['cert'];
    }

    public function getConfigPath(): string
    {
        return $this->paths['config'];
    }

    public function getLibPath(): string
    {
        return $this->paths['lib'];
    }

    public function getSchemasPath(): string
    {
        return $this->paths['lib'] . 'schemas/';
    }

    /**
     * Loads settings info from a settings Array
     *
     * @param array $settings SAML Toolkit Settings
     *
     * @return bool True if the settings info is valid
     */
    private function loadSettingsFromArray(array $settings)
    {
        if (isset($settings['sp'])) {
            $this->sp = $settings['sp'];
        }
        if (isset($settings['idp'])) {
            $this->idp = $settings['idp'];
        }

        $errors = $this->checkSettings($settings);
        if (empty($errors)) {
            $this->errors = [];

            if (isset($settings['strict'])) {
                $this->strict = $settings['strict'];
            }

            if (isset($settings['baseurl'])) {
                $this->baseurl = $settings['baseurl'];
            }

            if (isset($settings['compress'])) {
                $this->compress = $settings['compress'];
            }

            if (isset($settings['security'])) {
                $this->security = $settings['security'];
            }

            if (isset($settings['contactPerson'])) {
                $this->contacts = $settings['contactPerson'];
            }

            if (isset($settings['organization'])) {
                $this->organization = $settings['organization'];
            }

            $this->addDefaultValues();
            return true;
        }

        $this->errors = $errors;
        return false;
    }

    /**
     * Loads settings info from the settings file
     *
     * @return bool True if the settings info is valid
     *
     * @throws Error
     *
     * @suppress PhanUndeclaredVariable
     */
    private function loadSettingsFromFile()
    {
        $filename = $this->getConfigPath() . 'settings.php';

        if (!file_exists($filename)) {
            throw new Error(
                'Settings file not found: %s',
                Error::SETTINGS_FILE_NOT_FOUND,
                [$filename]
            );
        }

        /** @var array $settings */
        include $filename;

        // Add advance_settings if exists
        $advancedFilename = $this->getConfigPath() . 'advanced_settings.php';

        if (file_exists($advancedFilename)) {
            /** @var array $advancedSettings */
            include $advancedFilename;
            $settings = array_merge($settings, $advancedSettings);
        }

        return $this->loadSettingsFromArray($settings);
    }

    /**
     * Add default values if the settings info is not complete
     */
    private function addDefaultValues()
    {
        if (!isset($this->sp['assertionConsumerService']['binding'])) {
            $this->sp['assertionConsumerService']['binding'] = Constants::BINDING_HTTP_POST;
        }
        if (isset($this->sp['singleLogoutService']) && !isset($this->sp['singleLogoutService']['binding'])) {
            $this->sp['singleLogoutService']['binding'] = Constants::BINDING_HTTP_REDIRECT;
        }

        if (!isset($this->compress['requests'])) {
            $this->compress['requests'] = true;
        }

        if (!isset($this->compress['responses'])) {
            $this->compress['responses'] = true;
        }

        // Related to nameID
        if (!isset($this->sp['NameIDFormat'])) {
            $this->sp['NameIDFormat'] = Constants::NAMEID_UNSPECIFIED;
        }
        if (!isset($this->security['nameIdEncrypted'])) {
            $this->security['nameIdEncrypted'] = false;
        }
        if (!isset($this->security['requestedAuthnContext'])) {
            $this->security['requestedAuthnContext'] = true;
        }

        // sign provided
        if (!isset($this->security['authnRequestsSigned'])) {
            $this->security['authnRequestsSigned'] = false;
        }
        if (!isset($this->security['logoutRequestSigned'])) {
            $this->security['logoutRequestSigned'] = false;
        }
        if (!isset($this->security['logoutResponseSigned'])) {
            $this->security['logoutResponseSigned'] = false;
        }
        if (!isset($this->security['signMetadata'])) {
            $this->security['signMetadata'] = false;
        }

        // sign expected
        if (!isset($this->security['wantMessagesSigned'])) {
            $this->security['wantMessagesSigned'] = false;
        }
        if (!isset($this->security['wantAssertionsSigned'])) {
            $this->security['wantAssertionsSigned'] = false;
        }

        // NameID element expected
        if (!isset($this->security['wantNameId'])) {
            $this->security['wantNameId'] = true;
        }

        // Relax Destination validation
        if (!isset($this->security['relaxDestinationValidation'])) {
            $this->security['relaxDestinationValidation'] = false;
        }

        // encrypt expected
        if (!isset($this->security['wantAssertionsEncrypted'])) {
            $this->security['wantAssertionsEncrypted'] = false;
        }
        if (!isset($this->security['wantNameIdEncrypted'])) {
            $this->security['wantNameIdEncrypted'] = false;
        }

        // XML validation
        if (!isset($this->security['wantXMLValidation'])) {
            $this->security['wantXMLValidation'] = true;
        }

        // SignatureAlgorithm
        if (!isset($this->security['signatureAlgorithm'])) {
            $this->security['signatureAlgorithm'] = XMLSecurityKey::RSA_SHA256;
        }

        // DigestAlgorithm
        if (!isset($this->security['digestAlgorithm'])) {
            $this->security['digestAlgorithm'] = XMLSecurityDSig::SHA256;
        }

        if (!isset($this->security['lowercaseUrlencoding'])) {
            $this->security['lowercaseUrlencoding'] = false;
        }

        // Certificates / Private key /Fingerprint
        if (!isset($this->idp['x509cert'])) {
            $this->idp['x509cert'] = '';
        }
        if (!isset($this->idp['certFingerprint'])) {
            $this->idp['certFingerprint'] = '';
        }
        if (!isset($this->idp['certFingerprintAlgorithm'])) {
            $this->idp['certFingerprintAlgorithm'] = 'sha1';
        }

        if (!isset($this->sp['x509cert'])) {
            $this->sp['x509cert'] = '';
        }
        if (!isset($this->sp['privateKey'])) {
            $this->sp['privateKey'] = '';
        }
    }

    /**
     * Checks the settings info.
     *
     * @param array $settings Array with settings data
     *
     * @return array $errors  Errors found on the settings data
     */
    public function checkSettings(array $settings)
    {
        if (empty($settings)) {
            $errors = ['invalid_syntax'];
        } else {
            $errors = [];
            if (!$this->spValidationOnly) {
                $idpErrors = $this->checkIdPSettings($settings);
                $errors = array_merge($idpErrors, $errors);
            }
            $spErrors = $this->checkSPSettings($settings);
            $errors = array_merge($spErrors, $errors);

            $compressErrors = $this->checkCompressionSettings($settings);
            $errors = array_merge($compressErrors, $errors);
        }

        return $errors;
    }

    /**
     * Checks the compression settings info.
     *
     * @param array $settings Array with settings data
     *
     * @return array $errors  Errors found on the settings data
     */
    public function checkCompressionSettings($settings)
    {
        $errors = [];

        if (isset($settings['compress'])) {
            if (!is_array($settings['compress'])) {
                $errors[] = "invalid_syntax";
            } elseif (isset($settings['compress']['requests'])
                && $settings['compress']['requests'] !== true
                && $settings['compress']['requests'] !== false
            ) {
                $errors[] = "'compress'=>'requests' values must be true or false.";
            } elseif (isset($settings['compress']['responses'])
                && $settings['compress']['responses'] !== true
                && $settings['compress']['responses'] !== false
            ) {
                $errors[] = "'compress'=>'responses' values must be true or false.";
            }
        }
        return $errors;
    }

    /**
     * Checks the IdP settings info.
     *
     * @param array $settings Array with settings data
     *
     * @return array $errors  Errors found on the IdP settings data
     */
    public function checkIdPSettings(array $settings)
    {
        if (empty($settings)) {
            return ['invalid_syntax'];
        }

        $errors = [];

        if (!isset($settings['idp']) || empty($settings['idp'])) {
            $errors[] = 'idp_not_found';
        } else {
            $idp = $settings['idp'];
            if (!isset($idp['entityId']) || empty($idp['entityId'])) {
                $errors[] = 'idp_entityId_not_found';
            }

            if (!isset($idp['singleSignOnService'])
                || !isset($idp['singleSignOnService']['url'])
                || empty($idp['singleSignOnService']['url'])
            ) {
                $errors[] = 'idp_sso_not_found';
            } elseif (!filter_var($idp['singleSignOnService']['url'], FILTER_VALIDATE_URL)) {
                $errors[] = 'idp_sso_url_invalid';
            }

            if (isset($idp['singleLogoutService'])
                && isset($idp['singleLogoutService']['url'])
                && !empty($idp['singleLogoutService']['url'])
                && !filter_var($idp['singleLogoutService']['url'], FILTER_VALIDATE_URL)
            ) {
                $errors[] = 'idp_slo_url_invalid';
            }

            if (isset($settings['security'])) {
                $security = $settings['security'];

                $existsX509 = isset($idp['x509cert']) && !empty($idp['x509cert']);
                $existsMultiX509Sign = isset($idp['x509certMulti']) && isset($idp['x509certMulti']['signing']) && !empty($idp['x509certMulti']['signing']);
                $existsMultiX509Enc = isset($idp['x509certMulti']) && isset($idp['x509certMulti']['encryption']) && !empty($idp['x509certMulti']['encryption']);

                $existsFingerprint = isset($idp['certFingerprint']) && !empty($idp['certFingerprint']);
                if (!($existsX509 || $existsFingerprint || $existsMultiX509Sign)
                ) {
                    $errors[] = 'idp_cert_or_fingerprint_not_found_and_required';
                }
                if ((isset($security['nameIdEncrypted']) && $security['nameIdEncrypted'] === true)
                    && !($existsX509 || $existsMultiX509Enc)
                ) {
                    $errors[] = 'idp_cert_not_found_and_required';
                }
            }
        }

        return $errors;
    }

    /**
     * Checks the SP settings info.
     *
     * @param array $settings Array with settings data
     *
     * @return array $errors  Errors found on the SP settings data
     */
    public function checkSPSettings(array $settings)
    {
        if (empty($settings)) {
            return ['invalid_syntax'];
        }

        $errors = [];

        if (!isset($settings['sp']) || empty($settings['sp'])) {
            $errors[] = 'sp_not_found';
        } else {
            $sp = $settings['sp'];
            $security = [];
            if (isset($settings['security'])) {
                $security = $settings['security'];
            }

            if (!isset($sp['entityId']) || empty($sp['entityId'])) {
                $errors[] = 'sp_entityId_not_found';
            }

            if (!isset($sp['assertionConsumerService'])
                || !isset($sp['assertionConsumerService']['url'])
                || empty($sp['assertionConsumerService']['url'])
            ) {
                $errors[] = 'sp_acs_not_found';
            } elseif (!filter_var($sp['assertionConsumerService']['url'], FILTER_VALIDATE_URL)) {
                $errors[] = 'sp_acs_url_invalid';
            }

            if (isset($sp['singleLogoutService'])
                && isset($sp['singleLogoutService']['url'])
                && !filter_var($sp['singleLogoutService']['url'], FILTER_VALIDATE_URL)
            ) {
                $errors[] = 'sp_sls_url_invalid';
            }

            if (isset($security['signMetadata']) && is_array($security['signMetadata'])) {
                if (!isset($security['signMetadata']['keyFileName'])
                    || !isset($security['signMetadata']['certFileName'])
                ) {
                    $errors[] = 'sp_signMetadata_invalid';
                }
            }

            if (((isset($security['authnRequestsSigned']) && $security['authnRequestsSigned'] === true)
                || (isset($security['logoutRequestSigned']) && $security['logoutRequestSigned'] === true)
                || (isset($security['logoutResponseSigned']) && $security['logoutResponseSigned'] === true)
                || (isset($security['wantAssertionsEncrypted']) && $security['wantAssertionsEncrypted'] === true)
                || (isset($security['wantNameIdEncrypted']) && $security['wantNameIdEncrypted'] === true))
                && !$this->checkSPCerts()
            ) {
                $errors[] = 'sp_certs_not_found_and_required';
            }
        }

        if (isset($settings['contactPerson'])) {
            $types = array_keys($settings['contactPerson']);
            $validTypes = ['technical', 'support', 'administrative', 'billing', 'other'];
            foreach ($types as $type) {
                if (!in_array($type, $validTypes)) {
                    $errors[] = 'contact_type_invalid';
                    break;
                }
            }

            foreach ($settings['contactPerson'] as $contact) {
                if (!isset($contact['givenName']) || empty($contact['givenName'])
                    || !isset($contact['emailAddress']) || empty($contact['emailAddress'])
                ) {
                    $errors[] = 'contact_not_enought_data';
                    break;
                }
            }
        }

        if (isset($settings['organization'])) {
            foreach ($settings['organization'] as $organization) {
                if (!isset($organization['name']) || empty($organization['name'])
                    || !isset($organization['displayname']) || empty($organization['displayname'])
                    || !isset($organization['url']) || empty($organization['url'])
                ) {
                    $errors[] = 'organization_not_enought_data';
                    break;
                }
            }
        }

        return $errors;
    }

    /**
     * Checks if the x509 certs of the SP exists and are valid.
     *
     * @return bool
     */
    public function checkSPCerts()
    {
        $key = $this->getSPkey();
        $cert = $this->getSPcert();
        return !empty($key) && !empty($cert);
    }

    public function getSPkey(): ?string
    {
        $key = null;
        if (isset($this->sp['privateKey']) && !empty($this->sp['privateKey'])) {
            $key = $this->sp['privateKey'];
        } else {
            $keyFile = $this->paths['cert'] . 'sp.key';

            if (file_exists($keyFile)) {
                $key = file_get_contents($keyFile);
            }
        }
        return $key;
    }

    public function getSPcert(): ?string
    {
        $cert = null;

        if (isset($this->sp['x509cert']) && !empty($this->sp['x509cert'])) {
            $cert = $this->sp['x509cert'];
        } else {
            $certFile = $this->paths['cert'] . 'sp.crt';

            if (file_exists($certFile)) {
                $cert = file_get_contents($certFile);
            }
        }
        return $cert;
    }

    /**
     * Returns the x509 public of the SP that is
     * planed to be used soon instead the other
     * public cert
     */
    public function getSPcertNew(): ?string
    {
        $cert = null;

        if (isset($this->sp['x509certNew']) && !empty($this->sp['x509certNew'])) {
            $cert = $this->sp['x509certNew'];
        } else {
            $certFile = $this->paths['cert'] . 'sp_new.crt';

            if (file_exists($certFile)) {
                $cert = file_get_contents($certFile);
            }
        }
        return $cert;
    }

    /**
     * Gets the IdP data.
     *
     * @return array  IdP info
     */
    public function getIdPData()
    {
        return $this->idp;
    }

    /**
     * Gets the SP data.
     *
     * @return array  SP info
     */
    public function getSPData()
    {
        return $this->sp;
    }

    /**
     * Gets security data.
     *
     * @return array  SP info
     */
    public function getSecurityData()
    {
        return $this->security;
    }

    /**
     * Gets contact data.
     *
     * @return array  SP info
     */
    public function getContacts()
    {
        return $this->contacts;
    }

    /**
     * Gets organization data.
     *
     * @return array  SP info
     */
    public function getOrganization()
    {
        return $this->organization;
    }

    /**
     * Should SAML requests be compressed?
     *
     * @return bool Yes/No as True/False
     */
    public function shouldCompressRequests()
    {
        return $this->compress['requests'];
    }

    /**
     * Should SAML responses be compressed?
     *
     * @return bool Yes/No as True/False
     */
    public function shouldCompressResponses()
    {
        return $this->compress['responses'];
    }

    /**
     * Gets the SP metadata. The XML representation.
     *
     * @param bool $alwaysPublishEncryptionCert When 'true', the returned
     * metadata will always include an 'encryption' KeyDescriptor. Otherwise,
     * the 'encryption' KeyDescriptor will only be included if
     * $advancedSettings['security']['wantNameIdEncrypted'] or
     * $advancedSettings['security']['wantAssertionsEncrypted'] are enabled.
     * @param int|null      $validUntil    Metadata's valid time
     * @param int|null      $cacheDuration Duration of the cache in seconds
     *
     * @return string  SP metadata (xml)
     * @throws Exception
     * @throws Error
     */
    public function getSPMetadata($alwaysPublishEncryptionCert = false, $validUntil = null, $cacheDuration = null)
    {
        $metadata = Metadata::builder($this->sp, $this->security['authnRequestsSigned'], $this->security['wantAssertionsSigned'], $validUntil, $cacheDuration, $this->getContacts(), $this->getOrganization());

        $certNew = $this->getSPcertNew();
        if (!empty($certNew)) {
            $metadata = Metadata::addX509KeyDescriptors(
                $metadata,
                $certNew,
                $alwaysPublishEncryptionCert || $this->security['wantNameIdEncrypted'] || $this->security['wantAssertionsEncrypted']
            );
        }

        $cert = $this->getSPcert();
        if (!empty($cert)) {
            $metadata = Metadata::addX509KeyDescriptors(
                $metadata,
                $cert,
                $alwaysPublishEncryptionCert || $this->security['wantNameIdEncrypted'] || $this->security['wantAssertionsEncrypted']
            );
        }

        //Sign Metadata
        if (isset($this->security['signMetadata']) && $this->security['signMetadata'] !== false) {
            if ($this->security['signMetadata'] === true) {
                $keyMetadata = $this->getSPkey();
                $certMetadata = $cert;

                if (!$keyMetadata) {
                    throw new Error(
                        'SP Private key not found.',
                        Error::PRIVATE_KEY_FILE_NOT_FOUND
                    );
                }

                if (!$certMetadata) {
                    throw new Error(
                        'SP Public cert not found.',
                        Error::PUBLIC_CERT_FILE_NOT_FOUND
                    );
                }
            } else {
                if (!isset($this->security['signMetadata']['keyFileName'])
                    || !isset($this->security['signMetadata']['certFileName'])
                ) {
                    throw new Error(
                        'Invalid Setting: signMetadata value of the sp is not valid',
                        Error::SETTINGS_INVALID_SYNTAX
                    );
                }
                $keyFileName = $this->security['signMetadata']['keyFileName'];
                $certFileName = $this->security['signMetadata']['certFileName'];

                $keyMetadataFile = $this->paths['cert'] . $keyFileName;
                $certMetadataFile = $this->paths['cert'] . $certFileName;

                if (!file_exists($keyMetadataFile)) {
                    throw new Error(
                        'SP Private key file not found: %s',
                        Error::PRIVATE_KEY_FILE_NOT_FOUND,
                        [$keyMetadataFile]
                    );
                }

                if (!file_exists($certMetadataFile)) {
                    throw new Error(
                        'SP Public cert file not found: %s',
                        Error::PUBLIC_CERT_FILE_NOT_FOUND,
                        [$certMetadataFile]
                    );
                }
                $keyMetadata = file_get_contents($keyMetadataFile);
                $certMetadata = file_get_contents($certMetadataFile);
            }

            $signatureAlgorithm = $this->security['signatureAlgorithm'];
            $digestAlgorithm = $this->security['digestAlgorithm'];
            $metadata = Metadata::signMetadata($metadata, $keyMetadata, $certMetadata, $signatureAlgorithm, $digestAlgorithm);
        }
        return $metadata;
    }

    /**
     * @return array The list of found errors
     *
     * @throws Exception
     */
    public function validateMetadata(string $xml)
    {
        $errors = [];
        $res = Utils::validateXML($xml, 'saml-schema-metadata-2.0.xsd');
        if (!$res instanceof DOMDocument) {
            $errors[] = $res;
        } else {
            $dom = $res;
            $element = $dom->documentElement;
            if ($element->tagName !== 'md:EntityDescriptor') {
                $errors[] = 'noEntityDescriptor_xml';
            } else {
                $validUntil = $cacheDuration = null;

                if ($element->hasAttribute('validUntil')) {
                    $validUntil = Utils::parseSAML2Time($element->getAttribute('validUntil'));
                }
                if ($element->hasAttribute('cacheDuration')) {
                    $cacheDuration = $element->getAttribute('cacheDuration');
                }

                $expireTime = Utils::getExpireTime($cacheDuration, $validUntil);
                if (isset($expireTime) && time() > $expireTime) {
                    $errors[] = 'expired_xml';
                }
            }
        }

        // TODO: Support Metadata Sign Validation

        return $errors;
    }

    /**
     * Formats the IdP cert.
     */
    public function formatIdPCert()
    {
        if (isset($this->idp['x509cert'])) {
            $this->idp['x509cert'] = Utils::formatCert($this->idp['x509cert']);
        }
    }

    /**
     * Formats the Multple IdP certs.
     */
    public function formatIdPCertMulti()
    {
        if (isset($this->idp['x509certMulti'])) {
            if (isset($this->idp['x509certMulti']['signing'])) {
                foreach ($this->idp['x509certMulti']['signing'] as $i => $cert) {
                    $this->idp['x509certMulti']['signing'][$i] = Utils::formatCert($cert);
                }
            }
            if (isset($this->idp['x509certMulti']['encryption'])) {
                foreach ($this->idp['x509certMulti']['encryption'] as $i => $cert) {
                    $this->idp['x509certMulti']['encryption'][$i] = Utils::formatCert($cert);
                }
            }
        }
    }

    /**
     * Formats the SP cert.
     */
    public function formatSPCert()
    {
        if (isset($this->sp['x509cert'])) {
            $this->sp['x509cert'] = Utils::formatCert($this->sp['x509cert']);
        }
    }

    /**
     * Formats the SP cert.
     */
    public function formatSPCertNew()
    {
        if (isset($this->sp['x509certNew'])) {
            $this->sp['x509certNew'] = Utils::formatCert($this->sp['x509certNew']);
        }
    }

    /**
     * Formats the SP private key.
     */
    public function formatSPKey()
    {
        if (isset($this->sp['privateKey'])) {
            $this->sp['privateKey'] = Utils::formatPrivateKey($this->sp['privateKey']);
        }
    }

    /**
     * Returns an array with the errors, the array is empty when the settings is ok.
     *
     * @return array Errors
     */
    public function getErrors()
    {
        return $this->errors;
    }

    public function setStrict(bool $value)
    {
        $this->strict = $value;
    }

    /**
     * Returns if the 'strict' mode is active.
     *
     * @return bool Strict parameter
     */
    public function isStrict()
    {
        return $this->strict;
    }

    /**
     * Set a baseurl value.
     *
     * @param string $baseurl Base URL.
     */
    public function setBaseURL($baseurl)
    {
        $this->baseurl = $baseurl;
    }

    /**
     * Returns the baseurl set on the settings if any.
     *
     * @return null|string The baseurl
     */
    public function getBaseURL()
    {
        return $this->baseurl;
    }

    /**
     * Sets the IdP certificate.
     *
     * @param string $cert IdP certificate
     */
    public function setIdPCert($cert)
    {
        $this->idp['x509cert'] = $cert;
        $this->formatIdPCert();
    }
}
