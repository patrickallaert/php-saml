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
     * Initializes the settings:
     * - Sets the paths of the different folders
     * - Loads settings info from settings file or array/object provided
     *
     * @throws Error If any settings parameter is invalid
     * @throws Exception If Settings is incorrectly supplied
     */
    public function __construct(array $settings, bool $spValidationOnly = false)
    {
        $basePath = dirname(__DIR__, 2) . '/';
        $this->certPath = $basePath . 'certs/';

        if (defined('ONELOGIN_CUSTOMPATH')) {
            $this->certPath = ONELOGIN_CUSTOMPATH . 'certs/';
        }

        if (isset($settings['sp'])) {
            $this->sp = $settings['sp'];
        }
        if (isset($settings['idp'])) {
            $this->idp = $settings['idp'];
        }

        $errors = [];

        if (empty($settings)) {
            $errors[] = "invalid_syntax";
        }

        if (isset($settings['compress'])) {
            if (!is_array($settings['compress'])) {
                $errors[] = "invalid_syntax";
            } elseif (isset($settings['compress']['requests']) && !is_bool($settings['compress']['requests'])) {
                $errors[] = "'compress'=>'requests' values must be true or false.";
            } elseif (isset($settings['compress']['responses']) && !is_bool($settings['compress']['responses'])) {
                $errors[] = "'compress'=>'responses' values must be true or false.";
            }
        }

        if (empty($settings['sp'])) {
            $errors[] = 'sp_not_found';
        } else {
            $sp = $settings['sp'];

            if (empty($sp['entityId'])) {
                $errors[] = 'sp_entityId_not_found';
            }

            if (empty($sp['assertionConsumerService']['url'])) {
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
                if (empty($contact['givenName']) || empty($contact['emailAddress'])) {
                    $errors[] = 'contact_not_enough_data';
                    break;
                }
            }
        }

        if (isset($settings['organization'])) {
            foreach ($settings['organization'] as $organization) {
                if (empty($organization['name']) || empty($organization['displayname']) || empty($organization['url'])) {
                    $errors[] = 'organization_not_enough_data';
                    break;
                }
            }
        }

        if (!$spValidationOnly) {
            if (empty($settings['idp'])) {
                $errors[] = 'idp_not_found';
            } else {
                $idp = $settings['idp'];
                if (empty($idp['entityId'])) {
                    $errors[] = 'idp_entityId_not_found';
                }

                if (empty($idp['singleSignOnService']['url'])) {
                    $errors[] = 'idp_sso_not_found';
                } elseif (!filter_var($idp['singleSignOnService']['url'], FILTER_VALIDATE_URL)) {
                    $errors[] = 'idp_sso_url_invalid';
                }

                if (!empty($idp['singleLogoutService']['url'])
                    && !filter_var($idp['singleLogoutService']['url'], FILTER_VALIDATE_URL)
                ) {
                    $errors[] = 'idp_slo_url_invalid';
                }

                if (isset($settings['security'])) {
                    $security = $settings['security'];

                    $existsX509 = !empty($idp['x509cert']);
                    if (!(
                        $existsX509 ||
                        !empty($idp['certFingerprint']) ||
                        !empty($idp['x509certMulti']['signing'])
                    )) {
                        $errors[] = 'idp_cert_or_fingerprint_not_found_and_required';
                    }
                    if ((isset($security['nameIdEncrypted']) && $security['nameIdEncrypted'] === true)
                        && !($existsX509 || !empty($idp['x509certMulti']['encryption']))
                    ) {
                        $errors[] = 'idp_cert_not_found_and_required';
                    }
                }
            }
        }

        if (!empty($errors)) {
            $this->errors = $errors;
            throw new Error(
                'Invalid array settings: %s',
                Error::SETTINGS_INVALID,
                [implode(', ', $this->errors)]
            );
        }

        if (isset($settings['strict'])) {
            $this->strict = (bool) $settings['strict'];
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

        if (!isset($this->compress['requests'])) {
            $this->compress['requests'] = true;
        }

        if (!isset($this->compress['responses'])) {
            $this->compress['responses'] = true;
        }

        // sign provided
        if (!isset($this->security['signMetadata'])) {
            $this->security['signMetadata'] = false;
        }

        // Certificates / Private key /Fingerprint
        if (!isset($this->idp['x509cert'])) {
            $this->idp['x509cert'] = '';
        }

        if (!isset($this->sp['x509cert'])) {
            $this->sp['x509cert'] = '';
        }
        if (!isset($this->sp['privateKey'])) {
            $this->sp['privateKey'] = '';
        }

        $this->idp['x509cert'] = Utils::formatCert($this->idp['x509cert']);
        $this->sp['x509cert'] = Utils::formatCert($this->sp['x509cert']);
        $this->sp['privateKey'] = Utils::formatPrivateKey($this->sp['privateKey']);

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

    private function getSPFileContentHelper(string $spKey, string $fileName): ?string
    {
        if (!empty($this->sp[$spKey])) {
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
        return $this->getSPFileContentHelper("privateKey", "sp.key");
    }

    public function getSPcert(): ?string
    {
        return $this->getSPFileContentHelper("x509cert", "sp.crt");
    }

    /**
     * Returns the x509 public of the SP that is
     * planed to be used soon instead the other
     * public cert
     */
    public function getSPcertNew(): ?string
    {
        return $this->getSPFileContentHelper("x509certNew", "sp_new.crt");
    }

    public function getIdPX509Certificate(): string
    {
        return $this->idp['x509cert'];
    }

    public function getIdPMultipleX509SigningCertificate(): array
    {
        if (!empty($this->idp['x509certMulti']['signing'])) {
            return $this->idp['x509certMulti']['signing'];
        }

        return [];
    }

    public function getIdPOneEncryptionCertificate(): string
    {
        return $this->idp['x509certMulti']['encryption'][0] ?? $this->idp['x509cert'];
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

    public function getIdPCertFingerprint(): string
    {
        return $this->idp['certFingerprint'] ?? '';
    }

    public function getIdPCertFingerprintAlgorithm(): string
    {
        return $this->idp['certFingerprintAlgorithm'] ?? 'sha1';
    }

    public function hasSPAttributeConsumingService(): bool
    {
        return isset($this->sp['attributeConsumingService']);
    }

    public function getSPAttributeConsumingServiceDescription(): string
    {
        return $this->sp['attributeConsumingService']['serviceDescription'];
    }

    public function getSPAttributeConsumingServiceName(): string
    {
        return $this->sp['attributeConsumingService']['serviceName'] ?? 'Service';
    }

    public function getSPAttributeConsumingServiceRequestedAttributes(): array
    {
        return $this->sp['attributeConsumingService']['requestedAttributes'] ?? [];
    }

    public function getSPAssertionConsumerServiceUrl(): string
    {
        return $this->sp['assertionConsumerService']['url'];
    }

    public function getSPAssertionConsumerServiceBinding(): string
    {
        return $this->sp['assertionConsumerService']['binding'] ?? Constants::BINDING_HTTP_POST;
    }

    public function getSPEntityId(): string
    {
        return $this->sp['entityId'];
    }

    public function getSPNameIDFormat(): string
    {
        return $this->sp['NameIDFormat'] ?? Constants::NAMEID_UNSPECIFIED;
    }

    public function getSPSingleLogoutServiceUrl(): ?string
    {
        return $this->sp['singleLogoutService']['url'] ?? null;
    }

    public function getSPSingleLogoutServiceBinding(): string
    {
        return $this->sp['singleLogoutService']['binding'] ?? Constants::BINDING_HTTP_REDIRECT;
    }

    /**
     * @return bool|array
     */
    public function getSecurityRequestedAuthnContext()
    {
        return $this->security['requestedAuthnContext'] ?? true;
    }

    public function getSecurityRequestedAuthnContextComparison(): string
    {
        return $this->security['requestedAuthnContextComparison'] ?? 'exact';
    }

    public function getSecurityLowercaseUrlEncoding(): bool
    {
        return $this->security['lowercaseUrlencoding'] ?? false;
    }

    public function getSecurityAuthnRequestsSigned(): bool
    {
        return $this->security['authnRequestsSigned'] ?? false;
    }

    public function getSecurityWantAssertionsSigned(): bool
    {
        return $this->security['wantAssertionsSigned'] ?? false;
    }

    public function getSecurityWantAssertionsEncrypted(): bool
    {
        return $this->security['wantAssertionsEncrypted'] ?? false;
    }

    public function getSecurityWantXMLValidation(): bool
    {
        return $this->security['wantXMLValidation'] ?? true;
    }

    public function getSecurityNameIdEncrypted(): bool
    {
        return $this->security['nameIdEncrypted'] ?? false;
    }

    public function getSecurityWantNameId(): bool
    {
        return $this->security['wantNameId'] ?? true;
    }

    public function getSecurityWantNameIdEncrypted(): bool
    {
        return $this->security['wantNameIdEncrypted'] ?? false;
    }

    public function getSecurityWantMessagesSigned(): bool
    {
        return $this->security['wantMessagesSigned'] ?? false;
    }

    public function getSecurityWantLogoutRequestSigned(): bool
    {
        return $this->security['logoutRequestSigned'] ?? false;
    }

    public function getSecurityWantLogoutResponseSigned(): bool
    {
        return $this->security['logoutResponseSigned'] ?? false;
    }

    public function getSecuritySignatureAlgorithm(): string
    {
        return $this->security['signatureAlgorithm'] ?? XMLSecurityKey::RSA_SHA256;
    }

    private function getSecurityDigestAlgorithm(): string
    {
        return $this->security['digestAlgorithm'] ?? XMLSecurityDSig::SHA256;
    }

    public function getSecurityRelaxDestinationValidation(): bool
    {
        return $this->security['relaxDestinationValidation'] ?? false;
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
            $this,
            $validUntil,
            $cacheDuration
        );

        $certNew = $this->getSPcertNew();
        if (!empty($certNew)) {
            $metadata = Metadata::addX509KeyDescriptors(
                $metadata,
                $certNew,
                $alwaysPublishEncryptionCert || $this->getSecurityWantNameIdEncrypted() || $this->getSecurityWantAssertionsEncrypted()
            );
        }

        $cert = $this->getSPcert();
        if (!empty($cert)) {
            $metadata = Metadata::addX509KeyDescriptors(
                $metadata,
                $cert,
                $alwaysPublishEncryptionCert || $this->getSecurityWantNameIdEncrypted() || $this->getSecurityWantAssertionsEncrypted()
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
            $this->getSecuritySignatureAlgorithm(),
            $this->getSecurityDigestAlgorithm()
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
