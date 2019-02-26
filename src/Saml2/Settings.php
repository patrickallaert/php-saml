<?php
namespace OneLogin\Saml2;

use DOMDocument;
use Exception;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

class Settings
{
    /**
     * @var string
     */
    private $certPath;

    /**
     * @var string
     */
    private $configPath;

    /**
     * @var ?string
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
     * Validate SP data only flag
     *
     * @var bool
     */
    private $spValidationOnly;

    /**
     * Initializes the settings:
     * - Sets the paths of the different folders
     * - Loads settings info from settings file or array/object provided
     *
     * @throws Error If any settings parameter is invalid
     * @throws Exception If Settings is incorrectly supplied
     */
    public function __construct(array $settings, bool $spValidationOnly = false)
    {
        $this->spValidationOnly = $spValidationOnly;
        $basePath = dirname(__DIR__, 2) . '/';
        $this->certPath = $basePath . 'certs/';
        $this->configPath = $basePath;

        if (defined('ONELOGIN_CUSTOMPATH')) {
            $this->configPath = ONELOGIN_CUSTOMPATH;
            $this->certPath = ONELOGIN_CUSTOMPATH . 'certs/';
        }

        if (isset($settings['sp'])) {
            $this->sp = $settings['sp'];
        }
        if (isset($settings['idp'])) {
            $this->idp = $settings['idp'];
        }

        $errors = $this->checkSettings($settings);
        if (!empty($errors)) {
            $this->errors = $errors;
            throw new Error(
                'Invalid array settings: %s',
                Error::SETTINGS_INVALID,
                [implode(', ', $this->errors)]
            );
        }

        if (isset($settings['strict'])) {
            $this->strict = (bool)$settings['strict'];
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

        if (isset($this->idp['x509cert'])) {
            $this->idp['x509cert'] = Utils::formatCert($this->idp['x509cert']);
        }

        if (isset($this->sp['x509cert'])) {
            $this->sp['x509cert'] = Utils::formatCert($this->sp['x509cert']);
        }

        if (isset($this->sp['privateKey'])) {
            $this->sp['privateKey'] = Utils::formatPrivateKey($this->sp['privateKey']);
        }

        if (isset($this->sp['x509certNew'])) {
            $this->sp['x509certNew'] = Utils::formatCert($this->sp['x509certNew']);
        }

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

    public function checkSettings(array $settings): array
    {
        if (empty($settings)) {
            return ['invalid_syntax'];
        }

        $errors = [];

        if (isset($settings['compress'])) {
            if (!is_array($settings['compress'])) {
                $errors[] = "invalid_syntax";
            } elseif (isset($settings['compress']['requests']) && !is_bool($settings['compress']['requests'])) {
                $errors[] = "'compress'=>'requests' values must be true or false.";
            } elseif (isset($settings['compress']['responses']) && !is_bool($settings['compress']['responses'])) {
                $errors[] = "'compress'=>'responses' values must be true or false.";
            }
        }

        if (!isset($settings['sp']) || empty($settings['sp'])) {
            $errors[] = 'sp_not_found';
        } else {
            $sp = $settings['sp'];

            if (!isset($sp['entityId']) || empty($sp['entityId'])) {
                $errors[] = 'sp_entityId_not_found';
            }

            if (!isset($sp['assertionConsumerService']['url'])
                || empty($sp['assertionConsumerService']['url'])
            ) {
                $errors[] = 'sp_acs_not_found';
            } elseif (!filter_var($sp['assertionConsumerService']['url'], FILTER_VALIDATE_URL)) {
                $errors[] = 'sp_acs_url_invalid';
            }

            if (isset($sp['singleLogoutService']['url'])
                && !filter_var($sp['singleLogoutService']['url'], FILTER_VALIDATE_URL)
            ) {
                $errors[] = 'sp_sls_url_invalid';
            }

            $security = $settings['security'] ?? [];
            if (isset($security['signMetadata']) && is_array($security['signMetadata']) && !isset($security['signMetadata']['keyFileName'], $security['signMetadata']['certFileName'])) {
                $errors[] = 'sp_signMetadata_invalid';
            }

            if (((isset($security['authnRequestsSigned']) && $security['authnRequestsSigned'] === true)
                    || (isset($security['logoutRequestSigned']) && $security['logoutRequestSigned'] === true)
                    || (isset($security['logoutResponseSigned']) && $security['logoutResponseSigned'] === true)
                    || (isset($security['wantAssertionsEncrypted']) && $security['wantAssertionsEncrypted'] === true)
                    || (isset($security['wantNameIdEncrypted']) && $security['wantNameIdEncrypted'] === true))

                && (empty($this->getSPkey()) || empty($this->getSPcert()))
            ) {
                $errors[] = 'sp_certs_not_found_and_required';
            }
        }

        if (isset($settings['contactPerson'])) {
            foreach (array_keys($settings['contactPerson']) as $type) {
                switch ($type) {
                    case 'technical':
                    case 'support':
                    case 'administrative':
                    case 'billing':
                    case 'other':
                        break;
                    default:
                        $errors[] = 'contact_type_invalid';
                }
            }

            foreach ($settings['contactPerson'] as $contact) {
                if (!isset($contact['givenName'], $contact['emailAddress']) || empty($contact['givenName']) || empty($contact['emailAddress'])) {
                    $errors[] = 'contact_not_enough_data';
                    break;
                }
            }
        }

        if (isset($settings['organization'])) {
            foreach ($settings['organization'] as $organization) {
                if (!isset($organization['name'], $organization['displayname'], $organization['url']) ||
                    empty($organization['name']) || empty($organization['displayname']) || empty($organization['url'])
                ) {
                    $errors[] = 'organization_not_enough_data';
                    break;
                }
            }
        }

        if (!$this->spValidationOnly) {
            if (!isset($settings['idp']) || empty($settings['idp'])) {
                $errors[] = 'idp_not_found';
            } else {
                $idp = $settings['idp'];
                if (!isset($idp['entityId']) || empty($idp['entityId'])) {
                    $errors[] = 'idp_entityId_not_found';
                }

                if (!isset($idp['singleSignOnService']['url'])
                    || empty($idp['singleSignOnService']['url'])
                ) {
                    $errors[] = 'idp_sso_not_found';
                } elseif (!filter_var($idp['singleSignOnService']['url'], FILTER_VALIDATE_URL)) {
                    $errors[] = 'idp_sso_url_invalid';
                }

                if (isset($idp['singleLogoutService']['url'])
                    && !empty($idp['singleLogoutService']['url'])
                    && !filter_var($idp['singleLogoutService']['url'], FILTER_VALIDATE_URL)
                ) {
                    $errors[] = 'idp_slo_url_invalid';
                }

                if (isset($settings['security'])) {
                    $security = $settings['security'];

                    $existsX509 = isset($idp['x509cert']) && !empty($idp['x509cert']);
                    if (!(
                        $existsX509 ||
                        (isset($idp['certFingerprint']) && !empty($idp['certFingerprint'])) ||
                        (isset($idp['x509certMulti']['signing']) && !empty($idp['x509certMulti']['signing']))
                    )) {
                        $errors[] = 'idp_cert_or_fingerprint_not_found_and_required';
                    }
                    if ((isset($security['nameIdEncrypted']) && $security['nameIdEncrypted'] === true)
                        && !($existsX509 || (isset($idp['x509certMulti']['encryption']) && !empty($idp['x509certMulti']['encryption'])))
                    ) {
                        $errors[] = 'idp_cert_not_found_and_required';
                    }
                }
            }
        }

        return $errors;
    }

    private function getSpFileContentHelper(string $spKey, string $fileName): ?string
    {
        if (isset($this->sp[$spKey]) && !empty($this->sp[$spKey])) {
            return $this->sp[$spKey];
        }

        $file = $this->certPath . $fileName;

        if (file_exists($file)) {
            return file_get_contents($file);
        }

        return null;
    }

    public function getSPkey(): ?string
    {
        return $this->getSpFileContentHelper("privateKey", "sp.key");
    }

    public function getSPcert(): ?string
    {
        return $this->getSpFileContentHelper("x509cert", "sp.crt");
    }

    /**
     * Returns the x509 public of the SP that is
     * planed to be used soon instead the other
     * public cert
     */
    public function getSPcertNew(): ?string
    {
        return $this->getSpFileContentHelper("x509certNew", "sp_new.crt");
    }

    public function getIdPData(): array
    {
        return $this->idp;
    }

    public function getIdPEntityId(): string
    {
        return $this->idp['entityId'];
    }

    public function getIdPSingleSignOnServiceUrl(): string
    {
        return $this->idp['singleSignOnService']['url'];
    }

    public function getIdPSingleLogoutServiceUrl(): ?string
    {
        return $this->idp['singleLogoutService']['url'] ?? null;
    }

    public function getSPData(): array
    {
        return $this->sp;
    }

    public function getSPAssertionConsumerServiceUrl(): string
    {
        return $this->sp['assertionConsumerService']['url'];
    }

    public function getSPAssertionConsumerServiceBinding(): string
    {
        return $this->sp['assertionConsumerService']['binding'];
    }

    public function getSPEntityId(): string
    {
        return $this->sp['entityId'];
    }

    public function getSPNameIDFormat(): string
    {
        return $this->sp['NameIDFormat'];
    }

    public function getSPSingleLogoutServiceUrl(): string
    {
        return $this->sp['singleLogoutService']['url'];
    }

    public function getSecurityData(): array
    {
        return $this->security;
    }

    public function getContacts(): array
    {
        return $this->contacts;
    }

    public function getOrganization(): array
    {
        return $this->organization;
    }

    public function shouldCompressRequests(): bool
    {
        return $this->compress['requests'];
    }

    public function shouldCompressResponses(): bool
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
     *
     * @throws Exception
     * @throws Error
     */
    public function getSPMetadata(bool $alwaysPublishEncryptionCert = false, ?int $validUntil = null, ?int $cacheDuration = null): string
    {
        $metadata = Metadata::builder(
            $this->sp,
            $this->security['authnRequestsSigned'],
            $this->security['wantAssertionsSigned'],
            $validUntil,
            $cacheDuration,
            $this->getContacts(),
            $this->getOrganization()
        );

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
        if (!isset($this->security['signMetadata']) || $this->security['signMetadata'] === false) {
            return $metadata;
        }

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
            if (!isset($this->security['signMetadata']['keyFileName'], $this->security['signMetadata']['certFileName'])) {
                throw new Error(
                    'Invalid Setting: signMetadata value of the sp is not valid',
                    Error::SETTINGS_INVALID_SYNTAX
                );
            }
            $keyMetadataFile = $this->certPath . $this->security['signMetadata']['keyFileName'];
            $certMetadataFile = $this->certPath . $this->security['signMetadata']['certFileName'];

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

        return Utils::addSign(
            $metadata,
            $keyMetadata,
            $certMetadata,
            $this->security['signatureAlgorithm'],
            $this->security['digestAlgorithm']
        );
    }

    /**
     * @throws Exception
     */
    public function validateMetadata(string $xml): array
    {
        $dom = new DOMDocument();
        Utils::loadXML($dom, $xml);
        if (!Utils::validateXML($dom, 'saml-schema-metadata-2.0.xsd')) {
            return ["invalid_xml"];
        }

        $element = $dom->documentElement;
        if ($element->tagName !== 'md:EntityDescriptor') {
            return ['noEntityDescriptor_xml'];
        }

        $validUntil = $cacheDuration = null;

        if ($element->hasAttribute('validUntil')) {
            $validUntil = Utils::parseSAML2Time($element->getAttribute('validUntil'));
        }
        if ($element->hasAttribute('cacheDuration')) {
            $cacheDuration = $element->getAttribute('cacheDuration');
        }

        $expireTime = Utils::getExpireTime($cacheDuration, $validUntil);
        if ($expireTime !== null && time() > $expireTime) {
            return ['expired_xml'];
        }

        // TODO: Support Metadata Sign Validation

        return [];
    }

    /**
     * Returns an array with the errors, the array is empty when the settings is ok.
     */
    public function getErrors(): array
    {
        return $this->errors;
    }

    public function setStrict(bool $value): void
    {
        $this->strict = $value;
    }

    public function isStrict(): bool
    {
        return $this->strict;
    }

    /**
     * Returns the baseurl set on the settings if any.
     */
    public function getBaseURL(): ?string
    {
        return $this->baseurl;
    }
}
