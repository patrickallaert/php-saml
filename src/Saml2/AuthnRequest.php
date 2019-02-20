<?php
namespace OneLogin\Saml2;

/**
 * SAML 2 Authentication Request
 */
class AuthnRequest
{
    /**
     * @var Settings
     */
    protected $settings;

    /**
     * @var string
     */
    private $authnRequest;

    /**
     * @var string
     */
    private $id;

    public function __construct(Settings $settings, bool $forceAuthn = false, bool $isPassive = false, bool $setNameIdPolicy = true)
    {
        $this->settings = $settings;

        $spData = $this->settings->getSPData();
        $idpData = $this->settings->getIdPData();
        $security = $this->settings->getSecurityData();

        $this->id = Utils::generateUniqueID();
        $issueInstant = Utils::parseTime2SAML(time());

        $nameIdPolicyStr = '';
        if ($setNameIdPolicy) {
            $nameIDPolicyFormat = $spData['NameIDFormat'];
            if (isset($security['wantNameIdEncrypted']) && $security['wantNameIdEncrypted']) {
                $nameIDPolicyFormat = Constants::NAMEID_ENCRYPTED;
            }

            $nameIdPolicyStr = "<samlp:NameIDPolicy Format=\"{$nameIDPolicyFormat}\" AllowCreate=\"true\" />";
        }

        $providerNameStr = '';
        $organizationData = $settings->getOrganization();
        if (!empty($organizationData)) {
            $lang = isset($organizationData['en-US']) ? 'en-US' : array_keys($organizationData)[0];

            if (isset($organizationData[$lang]['displayname']) && !empty($organizationData[$lang]['displayname'])) {
                $providerNameStr = "ProviderName=\"{$organizationData[$lang]['displayname']}\"";
            }
        }

        $forceAuthnStr = $forceAuthn ? ' ForceAuthn="true"' : '';
        $isPassiveStr = $isPassive ? ' IsPassive="true"' : '';

        $requestedAuthnStr = '';
        if (isset($security['requestedAuthnContext']) && $security['requestedAuthnContext'] !== false) {
            $authnComparison = $security['requestedAuthnContextComparison'] ?? 'exact';

            if ($security['requestedAuthnContext'] === true) {
                $requestedAuthnStr = <<<REQUESTEDAUTHN
    <samlp:RequestedAuthnContext Comparison="$authnComparison">
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
    </samlp:RequestedAuthnContext>
REQUESTEDAUTHN;
            } else {
                $requestedAuthnStr .= "    <samlp:RequestedAuthnContext Comparison=\"$authnComparison\">\n";
                foreach ($security['requestedAuthnContext'] as $contextValue) {
                    $requestedAuthnStr .= "        <saml:AuthnContextClassRef>$contextValue</saml:AuthnContextClassRef>\n";
                }
                $requestedAuthnStr .= '    </samlp:RequestedAuthnContext>';
            }
        }

        $spEntityId = htmlspecialchars($spData['entityId'], ENT_QUOTES);
        $acsUrl = htmlspecialchars($spData['assertionConsumerService']['url'], ENT_QUOTES);
        $this->authnRequest = <<<AUTHNREQUEST
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="$this->id"
    Version="2.0"
{$providerNameStr}{$forceAuthnStr}{$isPassiveStr}
    IssueInstant="$issueInstant"
    Destination="{$idpData['singleSignOnService']['url']}"
    ProtocolBinding="{$spData['assertionConsumerService']['binding']}"
    AssertionConsumerServiceURL="{$acsUrl}">
    <saml:Issuer>{$spEntityId}</saml:Issuer>
{$nameIdPolicyStr}
{$requestedAuthnStr}
</samlp:AuthnRequest>
AUTHNREQUEST;
    }

    /**
     * Returns deflated, base64 encoded, unsigned AuthnRequest.
     */
    public function getRequest(?bool $deflate = null): string
    {
        $subject = $this->authnRequest;

        if ($deflate === null) {
            $deflate = $this->settings->shouldCompressRequests();
        }

        if ($deflate) {
            $subject = gzdeflate($this->authnRequest);
        }

        return base64_encode($subject);
    }

    public function getId(): string
    {
        return $this->id;
    }
}
