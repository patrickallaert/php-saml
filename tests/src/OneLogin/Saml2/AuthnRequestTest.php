<?php

namespace Saml2\Tests;

use Saml2\AuthnRequest;
use Saml2\Settings;
use Saml2\Utils;

class AuthnRequestTest extends \PHPUnit\Framework\TestCase
{
    private $settings;


    public function setUp(): void
    {
        $this->settings = new Settings(require TEST_ROOT . '/settings/settings1.php');
    }

    /**
     * The creation of a deflated SAML Request
     *
     * @covers \Saml2\AuthnRequest
     */
    public function testCreateDeflatedSAMLRequestURLParameter()
    {
        $authUrl = Utils::redirect('http://idp.example.com/SSOService.php', ['SAMLRequest' => (new AuthnRequest($this->settings))->getRequest()], true);
        $this->assertRegExp('#^http://idp\.example\.com\/SSOService\.php\?SAMLRequest=#', $authUrl);
        parse_str(parse_url($authUrl, PHP_URL_QUERY), $exploded);
        // parse_url already urldecode de params so is not required.
        $this->assertRegExp('#^<samlp:AuthnRequest#', gzinflate(base64_decode($exploded['SAMLRequest'])));
    }

    /**
     * The creation of a deflated SAML Request with AuthNContext
     *
     * @covers \Saml2\AuthnRequest
     */
    public function testAuthNContext()
    {
        $settingsInfo = require TEST_ROOT . '/settings/settings1.php';

        $request = gzinflate(base64_decode((new AuthnRequest(new Settings($settingsInfo)))->getRequest()));
        $this->assertStringContainsString('<samlp:RequestedAuthnContext Comparison="exact">', $request);
        $this->assertStringContainsString('<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>', $request);

        $settingsInfo['security']['requestedAuthnContext'] = true;
        $request2 = gzinflate(base64_decode((new AuthnRequest(new Settings($settingsInfo)))->getRequest()));
        $this->assertStringContainsString('<samlp:RequestedAuthnContext Comparison="exact">', $request2);
        $this->assertStringContainsString('<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>', $request2);

        $settingsInfo['security']['requestedAuthnContext'] = false;
        $request3 = gzinflate(base64_decode((new AuthnRequest(new Settings($settingsInfo)))->getRequest()));
        $this->assertStringNotContainsString('<samlp:RequestedAuthnContext Comparison="exact">', $request3);
        $this->assertStringNotContainsString('<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>', $request3);

        $settingsInfo['security']['requestedAuthnContext'] = ['urn:oasis:names:tc:SAML:2.0:ac:classes:Password', 'urn:oasis:names:tc:SAML:2.0:ac:classes:X509'];
        $request4 = gzinflate(base64_decode((new AuthnRequest(new Settings($settingsInfo)))->getRequest()));
        $this->assertStringContainsString('<samlp:RequestedAuthnContext Comparison="exact">', $request4);
        $this->assertStringNotContainsString('<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>', $request4);
        $this->assertStringContainsString('<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>', $request4);
        $this->assertStringContainsString('<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:X509</saml:AuthnContextClassRef>', $request4);

        $settingsInfo['security']['requestedAuthnContextComparison'] = 'minimum';
        $this->assertStringContainsString(
            '<samlp:RequestedAuthnContext Comparison="minimum">',
            gzinflate(
                base64_decode(
                    (new AuthnRequest(new Settings($settingsInfo)))->getRequest()
                )
            )
        );
    }

    /**
     * The creation of a deflated SAML Request with ForceAuthn
     *
     * @covers \Saml2\AuthnRequest
     */
    public function testForceAuthN()
    {
        $settings = new Settings(require TEST_ROOT . '/settings/settings1.php');
        $this->assertStringNotContainsString('ForceAuthn="true"', gzinflate(base64_decode((new AuthnRequest($settings))->getRequest())));
        $this->assertStringNotContainsString('ForceAuthn="true"', gzinflate(base64_decode((new AuthnRequest($settings, false, false))->getRequest())));
        $this->assertStringContainsString('ForceAuthn="true"', gzinflate(base64_decode((new AuthnRequest($settings, true, false))->getRequest())));
    }

    /**
     * The creation of a deflated SAML Request with isPassive
     *
     * @covers \Saml2\AuthnRequest
     */
    public function testIsPassive()
    {
        $settings = new Settings(require TEST_ROOT . '/settings/settings1.php');
        $this->assertStringNotContainsString('IsPassive="true"', gzinflate(base64_decode((new AuthnRequest($settings))->getRequest())));
        $this->assertStringNotContainsString('IsPassive="true"', gzinflate(base64_decode((new AuthnRequest($settings, false, false))->getRequest())));
        $this->assertStringContainsString('IsPassive="true"', gzinflate(base64_decode((new AuthnRequest($settings, false, true))->getRequest())));
    }

    /**
     * The creation of a deflated SAML Request with and without NameIDPolicy
     *
     * @covers \Saml2\AuthnRequest
     */
    public function testNameIDPolicy()
    {
        $settings = new Settings(require TEST_ROOT . '/settings/settings1.php');
        $this->assertStringNotContainsString('<samlp:NameIDPolicy', gzinflate(base64_decode((new AuthnRequest($settings, false, false, false))->getRequest())));
        $this->assertStringContainsString('<samlp:NameIDPolicy', gzinflate(base64_decode((new AuthnRequest($settings, false, false, true))->getRequest())));
        $this->assertStringContainsString('<samlp:NameIDPolicy', gzinflate(base64_decode((new AuthnRequest($settings))->getRequest())));
    }

    /**
     * The creation of a deflated SAML Request
     *
     * @covers \Saml2\AuthnRequest
     */
    public function testCreateEncSAMLRequest()
    {
        $settingsInfo = require TEST_ROOT . '/settings/settings1.php';

        $settingsInfo['organization'] = [
            'es' => [
                'name' => 'sp_prueba',
                'displayname' => 'SP prueba',
                'url' => 'http://sp.example.com',
            ],
        ];
        $settingsInfo['security']['wantNameIdEncrypted'] = true;

        $authUrl = Utils::redirect(
            'http://idp.example.com/SSOService.php',
            ['SAMLRequest' => (new AuthnRequest(new Settings($settingsInfo)))->getRequest()],
            true
        );
        $this->assertRegExp('#^http://idp\.example\.com\/SSOService\.php\?SAMLRequest=#', $authUrl);
        parse_str(parse_url($authUrl, PHP_URL_QUERY), $exploded);
        // parse_url already urldecode de params so is not required.
        $message = gzinflate(base64_decode($exploded['SAMLRequest']));
        $this->assertRegExp('#^<samlp:AuthnRequest#', $message);
        $this->assertRegExp('#AssertionConsumerServiceURL="http://stuff.com/endpoints/endpoints/acs.php">#', $message);
        $this->assertRegExp('#<saml:Issuer>http://stuff.com/endpoints/metadata.php</saml:Issuer>#', $message);
        $this->assertRegExp('#Format="urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted"#', $message);
        $this->assertRegExp('#ProviderName="SP prueba"#', $message);
    }

    /**
     * Tests that a 'true' value for compress => requests gets honored when we
     * try to obtain the request payload from getRequest()
     *
     * @covers \Saml2\AuthnRequest::getRequest()
     */
    public function testWeCanChooseToCompressARequest()
    {
        //Test that we can compress.
        $this->assertRegExp('#^<samlp:AuthnRequest#', gzinflate(base64_decode((new AuthnRequest(new Settings(require TEST_ROOT . '/settings/settings1.php')))->getRequest())));
    }

    /**
     * Tests that a 'false' value for compress => requests gets honored when we
     * try to obtain the request payload from getRequest()
     *
     * @covers \Saml2\AuthnRequest::getRequest()
     */
    public function testWeCanChooseNotToCompressARequest()
    {
        //Test that we can choose not to compress the request payload.
        $this->assertRegExp('#^<samlp:AuthnRequest#', base64_decode((new AuthnRequest(new Settings(require TEST_ROOT . '/settings/settings2.php')))->getRequest()));
    }

    /**
     * Tests that we can pass a boolean value to the getRequest()
     * method to choose whether it should 'gzdeflate' the body
     * of the request.
     *
     * @covers \Saml2\AuthnRequest::getRequest()
     */
    public function testWeCanChooseToDeflateARequestBody()
    {
        //Test that we can choose not to compress the request payload.
        //Compression is currently turned on in settings.
        $this->assertRegExp('#^<samlp:AuthnRequest#', base64_decode((new AuthnRequest(new Settings(require TEST_ROOT . '/settings/settings1.php')))->getRequest(false)));

        //Test that we can choose not to compress the request payload.
        //Compression is currently turned off in settings.
        $this->assertRegExp('#^<samlp:AuthnRequest#', gzinflate(base64_decode((new AuthnRequest(new Settings(require TEST_ROOT . '/settings/settings2.php')))->getRequest(true))));
    }
}
