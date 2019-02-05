<?php

namespace OneLogin\Saml2\Tests;

use OneLogin\Saml2\AuthnRequest;
use OneLogin\Saml2\Settings;
use OneLogin\Saml2\Utils;

class AuthnRequestTest extends \PHPUnit\Framework\TestCase
{
    private $settings;


    public function setUp()
    {
        include TEST_ROOT . '/settings/settings1.php';

        $this->settings = new Settings($settingsInfo);
    }

    /**
     * The creation of a deflated SAML Request
     *
     * @covers OneLogin\Saml2\AuthnRequest
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
     * @covers OneLogin\Saml2\AuthnRequest
     */
    public function testAuthNContext()
    {
        include TEST_ROOT . '/settings/settings1.php';

        $request = gzinflate(base64_decode((new AuthnRequest(new Settings($settingsInfo)))->getRequest()));
        $this->assertContains('<samlp:RequestedAuthnContext Comparison="exact">', $request);
        $this->assertContains('<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>', $request);

        $settingsInfo['security']['requestedAuthnContext'] = true;
        $request2 = gzinflate(base64_decode((new AuthnRequest(new Settings($settingsInfo)))->getRequest()));
        $this->assertContains('<samlp:RequestedAuthnContext Comparison="exact">', $request2);
        $this->assertContains('<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>', $request2);

        $settingsInfo['security']['requestedAuthnContext'] = false;
        $request3 = gzinflate(base64_decode((new AuthnRequest(new Settings($settingsInfo)))->getRequest()));
        $this->assertNotContains('<samlp:RequestedAuthnContext Comparison="exact">', $request3);
        $this->assertNotContains('<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>', $request3);

        $settingsInfo['security']['requestedAuthnContext'] = ['urn:oasis:names:tc:SAML:2.0:ac:classes:Password', 'urn:oasis:names:tc:SAML:2.0:ac:classes:X509'];
        $request4 = gzinflate(base64_decode((new AuthnRequest(new Settings($settingsInfo)))->getRequest()));
        $this->assertContains('<samlp:RequestedAuthnContext Comparison="exact">', $request4);
        $this->assertNotContains('<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>', $request4);
        $this->assertContains('<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>', $request4);
        $this->assertContains('<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:X509</saml:AuthnContextClassRef>', $request4);

        $settingsInfo['security']['requestedAuthnContextComparison'] = 'minimum';
        $this->assertContains(
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
     * @covers OneLogin\Saml2\AuthnRequest
     */
    public function testForceAuthN()
    {
        include TEST_ROOT . '/settings/settings1.php';

        $settings = new Settings($settingsInfo);
        $this->assertNotContains('ForceAuthn="true"', gzinflate(base64_decode((new AuthnRequest($settings))->getRequest())));
        $this->assertNotContains('ForceAuthn="true"', gzinflate(base64_decode((new AuthnRequest($settings, false, false))->getRequest())));
        $this->assertContains('ForceAuthn="true"', gzinflate(base64_decode((new AuthnRequest($settings, true, false))->getRequest())));
    }

    /**
     * The creation of a deflated SAML Request with isPassive
     *
     * @covers OneLogin\Saml2\AuthnRequest
     */
    public function testIsPassive()
    {
        include TEST_ROOT . '/settings/settings1.php';

        $settings = new Settings($settingsInfo);
        $this->assertNotContains('IsPassive="true"', gzinflate(base64_decode((new AuthnRequest($settings))->getRequest())));
        $this->assertNotContains('IsPassive="true"', gzinflate(base64_decode((new AuthnRequest($settings, false, false))->getRequest())));
        $this->assertContains('IsPassive="true"', gzinflate(base64_decode((new AuthnRequest($settings, false, true))->getRequest())));
    }

    /**
     * The creation of a deflated SAML Request with and without NameIDPolicy
     *
     * @covers OneLogin\Saml2\AuthnRequest
     */
    public function testNameIDPolicy()
    {
        include TEST_ROOT . '/settings/settings1.php';

        $settings = new Settings($settingsInfo);
        $this->assertNotContains('<samlp:NameIDPolicy', gzinflate(base64_decode((new AuthnRequest($settings, false, false, false))->getRequest())));
        $this->assertContains('<samlp:NameIDPolicy', gzinflate(base64_decode((new AuthnRequest($settings, false, false, true))->getRequest())));
        $this->assertContains('<samlp:NameIDPolicy', gzinflate(base64_decode((new AuthnRequest($settings))->getRequest())));
    }

    /**
     * The creation of a deflated SAML Request
     *
     * @covers OneLogin\Saml2\AuthnRequest
     */
    public function testCreateEncSAMLRequest()
    {
        include TEST_ROOT . '/settings/settings1.php';

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
     * @covers OneLogin\Saml2\AuthnRequest::getRequest()
     */
    public function testWeCanChooseToCompressARequest()
    {
        //Test that we can compress.
        include TEST_ROOT . '/settings/settings1.php';

        $this->assertRegExp('#^<samlp:AuthnRequest#', gzinflate(base64_decode((new AuthnRequest(new Settings($settingsInfo)))->getRequest())));
    }

    /**
     * Tests that a 'false' value for compress => requests gets honored when we
     * try to obtain the request payload from getRequest()
     *
     * @covers OneLogin\Saml2\AuthnRequest::getRequest()
     */
    public function testWeCanChooseNotToCompressARequest()
    {
        //Test that we can choose not to compress the request payload.
        include TEST_ROOT . '/settings/settings2.php';

        $this->assertRegExp('#^<samlp:AuthnRequest#', base64_decode((new AuthnRequest(new Settings($settingsInfo)))->getRequest()));
    }

    /**
     * Tests that we can pass a boolean value to the getRequest()
     * method to choose whether it should 'gzdeflate' the body
     * of the request.
     *
     * @covers OneLogin\Saml2\AuthnRequest::getRequest()
     */
    public function testWeCanChooseToDeflateARequestBody()
    {
        //Test that we can choose not to compress the request payload.
        include TEST_ROOT . '/settings/settings1.php';

        //Compression is currently turned on in settings.
        $this->assertRegExp('#^<samlp:AuthnRequest#', base64_decode((new AuthnRequest(new Settings($settingsInfo)))->getRequest(false)));

        //Test that we can choose not to compress the request payload.
        include TEST_ROOT . '/settings/settings2.php';

        //Compression is currently turned off in settings.
        $this->assertRegExp('#^<samlp:AuthnRequest#', gzinflate(base64_decode((new AuthnRequest(new Settings($settingsInfo)))->getRequest(true))));
    }

    /**
     * Tests that we can get the request XML directly without
     * going through intermediate steps
     *
     * @covers OneLogin\Saml2\AuthnRequest::getXML()
     */
    public function testGetXML()
    {
        include TEST_ROOT . '/settings/settings1.php';

        $this->assertRegExp('#^<samlp:AuthnRequest#', (new AuthnRequest(new Settings($settingsInfo)))->getXML());
    }
}
