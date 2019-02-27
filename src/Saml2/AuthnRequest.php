<?php
namespace Saml2;

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

        $ssoServiceUrl = $this->settings->getIdPSingleSignOnServiceUrl();

        $this->id = Utils::generateUniqueID();
        $issueInstant = Utils::parseTime2SAML(time());

        $nameIdPolicyStr = '';
        if ($setNameIdPolicy) {
            $nameIDPolicyFormat = $this->settings->getSPNameIDFormat();
            if ($this->settings->getSecurityWantNameIdEncrypted()) {
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
        if ($requestedAuthnContext = $this->settings->getSecurityRequestedAuthnContext()) {
            $authnComparison = $this->settings->getSecurityRequestedAuthnContextComparison();

            if ($requestedAuthnContext === true) {
                $requestedAuthnStr = <<<REQUESTEDAUTHN
    <samlp:RequestedAuthnContext Comparison="$authnComparison">
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
    </samlp:RequestedAuthnContext>
REQUESTEDAUTHN;
            } else {
                $requestedAuthnStr .= "    <samlp:RequestedAuthnContext Comparison=\"$authnComparison\">\n";
                foreach ($requestedAuthnContext as $contextValue) {
                    $requestedAuthnStr .= "        <saml:AuthnContextClassRef>$contextValue</saml:AuthnContextClassRef>\n";
                }
                $requestedAuthnStr .= '    </samlp:RequestedAuthnContext>';
            }
        }

        $spEntityId = htmlspecialchars($this->settings->getSPEntityId(), ENT_QUOTES);
        $acsUrl = htmlspecialchars($this->settings->getSPAssertionConsumerServiceUrl(), ENT_QUOTES);
        $acsBinding = $this->settings->getSPAssertionConsumerServiceBinding();
        $this->authnRequest = <<<AUTHNREQUEST
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="$this->id"
    Version="2.0"
{$providerNameStr}{$forceAuthnStr}{$isPassiveStr}
    IssueInstant="$issueInstant"
    Destination="$ssoServiceUrl"
    ProtocolBinding="$acsBinding"
    AssertionConsumerServiceURL="$acsUrl">
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
