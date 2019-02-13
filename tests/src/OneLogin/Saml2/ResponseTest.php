<?php

namespace OneLogin\Saml2\Tests;

use DOMDocument;
use OneLogin\Saml2\Constants;
use OneLogin\Saml2\Response;
use OneLogin\Saml2\Settings;
use OneLogin\Saml2\Utils;
use OneLogin\Saml2\ValidationError;

class ResponseTest extends \PHPUnit\Framework\TestCase
{
    private $settings;

    public function setUp()
    {
        include TEST_ROOT . '/settings/settings1.php';

        $this->settings = new Settings($settingsInfo);
    }

    /**
     * @covers OneLogin\Saml2\Response
     */
    public function testConstruct()
    {
        $response = new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/response1.xml.base64'));

        $this->assertTrue($response instanceof Response);

        $responseEnc = new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64'));

        $this->assertTrue($responseEnc instanceof Response);
    }

    /**
     * Tests that we can retrieve the ID of the Response
     *
     * @covers OneLogin\Saml2\Response::getId()
     */
    public function testGetId()
    {
        $this->assertSame(
            'pfxc3d2b542-0f7e-8767-8e87-5b0dc6913375',
            (new Response(
                $this->settings,
                base64_encode(file_get_contents(TEST_ROOT . '/data/responses/signed_message_response.xml'))
            ))->getId()
        );
    }

    /**
     * Tests that we can retrieve the ID of the Response
     *
     * @covers OneLogin\Saml2\Response::getAssertionId()
     */
    public function testGetAssertionId()
    {
        $this->assertSame(
            '_cccd6024116641fe48e0ae2c51220d02755f96c98d',
            (new Response(
                $this->settings,
                base64_encode(file_get_contents(TEST_ROOT . '/data/responses/signed_message_response.xml'))
            ))->getAssertionId()
        );
    }

    /**
     * Tests that we can retrieve attributes when specific namespace
     *
     * @covers OneLogin\Saml2\Response::getAttributes()
     */
    public function testNamespaces()
    {
        $this->assertSame(
            [
                'FirstName' => ['Someone'],
                'LastName' => ['Special'],
            ],
            (new Response($this->settings, base64_encode(file_get_contents(TEST_ROOT . '/data/responses/open_saml_response.xml'))))->getAttributes()
        );
    }

    /**
     * @covers OneLogin\Saml2\Response::getNameId
     */
    public function testReturnNameId()
    {
        $this->assertSame(
            'support@onelogin.com',
            (new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/response1.xml.base64')))->getNameId()
        );

        $this->assertSame(
            '2de11defd199f8d5bb63f9b7deb265ba5c675c10',
            (new Response(
                $this->settings,
                file_get_contents(TEST_ROOT . '/data/responses/response_encrypted_nameid.xml.base64')
            ))->getNameId()
        );

        $this->assertSame(
            '_68392312d490db6d355555cfbbd8ec95d746516f60',
            (new Response(
                $this->settings,
                file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64')
            ))->getNameId()
        );

        $xml4 = file_get_contents(TEST_ROOT . '/data/responses/invalids/no_nameid.xml.base64');
        try {
            (new Response($this->settings, $xml4))->getNameId();
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertContains('NameID not found in the assertion of the Response', $e->getMessage());
        }

        include TEST_ROOT . '/settings/settings1.php';

        $settingsInfo['security']['wantNameId'] = true;

        try {
            (new Response(new Settings($settingsInfo), $xml4))->getNameId();
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertContains('NameID not found in the assertion of the Response', $e->getMessage());
        }

        $settingsInfo['security']['wantNameId'] = false;

        $this->assertNull((new Response(new Settings($settingsInfo), $xml4))->getNameId());

        unset($settingsInfo['security']['wantNameId']);
        $settings = new Settings($settingsInfo);
        try {
            (new Response($settings, $xml4))->getNameId();
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertContains('NameID not found in the assertion of the Response', $e->getMessage());
        }

        $xml5 = file_get_contents(TEST_ROOT . '/data/responses/wrong_spnamequalifier.xml.base64');
        $this->assertSame('492882615acf31c8096b627245d76ae53036c090', (new Response($settings, $xml5))->getNameId());

        $xml6 = file_get_contents(TEST_ROOT . '/data/responses/invalids/empty_nameid.xml.base64');
        $this->assertEmpty((new Response($settings, $xml6))->getNameId());

        $settingsInfo['strict'] = true;
        $settings = new Settings($settingsInfo);
        try {
            (new Response($settings, $xml5))->getNameId();
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertContains('The SPNameQualifier value mismatch the SP entityID value.', $e->getMessage());
        }

        try {
            (new Response($settings, $xml6))->getNameId();
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertContains('An empty NameID value found', $e->getMessage());
        }
    }

    /**
     * @covers OneLogin\Saml2\Response::getNameIdFormat
     */
    public function testGetNameIdFormat()
    {
        $this->assertSame(
            Constants::NAMEID_EMAIL_ADDRESS,
            (new Response(
                $this->settings,
                file_get_contents(TEST_ROOT . '/data/responses/response1.xml.base64')
            ))->getNameIdFormat()
        );

        $this->assertSame(
            Constants::NAMEID_UNSPECIFIED,
            (new Response(
                $this->settings,
                file_get_contents(TEST_ROOT . '/data/responses/response_encrypted_nameid.xml.base64')
            ))->getNameIdFormat()
        );

        $this->assertSame(
            Constants::NAMEID_TRANSIENT,
            (new Response(
                $this->settings,
                file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64')
            ))->getNameIdFormat()
        );

        try {
            (new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/invalids/no_nameid.xml.base64')))->getNameIdFormat();
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertContains('NameID not found in the assertion of the Response', $e->getMessage());
        }
    }

    /**
     * @covers OneLogin\Saml2\Response::getNameIdNameQualifier
     */
    public function testGetNameIdNameQualifier()
    {
        $this->assertSame(
            'https://test.example.com/saml/metadata',
            (new Response(
                $this->settings,
                file_get_contents(TEST_ROOT . '/data/responses/response1.xml.base64')
            ))->getNameIdNameQualifier()
        );
        $this->assertNull(
            (new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/response_encrypted_nameid.xml.base64')))->getNameIdNameQualifier()
        );
        $this->assertNull(
            (new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64')))->getNameIdNameQualifier()
        );
        try {
            (new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/invalids/no_nameid.xml.base64')))->getNameIdNameQualifier();
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertContains('NameID not found in the assertion of the Response', $e->getMessage());
        }
    }

    /**
     * @covers OneLogin\Saml2\Response::getNameIdSPNameQualifier
     */
    public function testGetNameIdSPNameQualifier()
    {
        $this->assertNull((new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/response1.xml.base64')))->getNameIdSPNameQualifier());
        $this->assertSame(
            'http://stuff.com/endpoints/metadata.php',
            (new Response(
                $this->settings,
                file_get_contents(TEST_ROOT . '/data/responses/response_encrypted_nameid.xml.base64')
            ))->getNameIdSPNameQualifier()
        );
        $this->assertSame(
            'http://stuff.com/endpoints/metadata.php',
            (new Response(
                $this->settings,
                file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64')
            ))->getNameIdSPNameQualifier()
        );
        $this->assertSame(
            'http://stuff.com/endpoints/metadata.php',
            (new Response(
                $this->settings,
                file_get_contents(TEST_ROOT . '/data/responses/valid_response.xml.base64')
            ))->getNameIdSPNameQualifier()
        );
        try {
            (new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/invalids/no_nameid.xml.base64')))->getNameIdSPNameQualifier();
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertContains('NameID not found in the assertion of the Response', $e->getMessage());
        }
    }

    /**
     * @covers OneLogin\Saml2\Response::getNameIdData
     */
    public function testGetNameIdData()
    {
        $this->assertSame(
            [
                'Value' => 'support@onelogin.com',
                'Format' => Constants::NAMEID_EMAIL_ADDRESS,
                'NameQualifier' => 'https://test.example.com/saml/metadata',
            ],
            (new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/response1.xml.base64')))->getNameIdData()
        );

        $this->assertSame(
            [
                'Value' => '2de11defd199f8d5bb63f9b7deb265ba5c675c10',
                'Format' => Constants::NAMEID_UNSPECIFIED,
                'SPNameQualifier' => 'http://stuff.com/endpoints/metadata.php',
            ],
            (new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/response_encrypted_nameid.xml.base64')))->getNameIdData()
        );

        $this->assertSame(
            [
                'Value' => '_68392312d490db6d355555cfbbd8ec95d746516f60',
                'Format' => Constants::NAMEID_TRANSIENT,
                'SPNameQualifier' => 'http://stuff.com/endpoints/metadata.php',
            ],
            (new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64')))->getNameIdData()
        );

        $xml4 = file_get_contents(TEST_ROOT . '/data/responses/invalids/no_nameid.xml.base64');
        try {
            (new Response($this->settings, $xml4))->getNameIdData();
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertContains('NameID not found in the assertion of the Response', $e->getMessage());
        }

        include TEST_ROOT . '/settings/settings1.php';

        $settingsInfo['security']['wantNameId'] = true;

        try {
            (new Response(new Settings($settingsInfo), $xml4))->getNameIdData();
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertContains('NameID not found in the assertion of the Response', $e->getMessage());
        }

        $settingsInfo['security']['wantNameId'] = false;

        $this->assertEmpty((new Response(new Settings($settingsInfo), $xml4))->getNameIdData());

        unset($settingsInfo['security']['wantNameId']);
        $settings = new Settings($settingsInfo);
        try {
            (new Response($settings, $xml4))->getNameIdData();
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertContains('NameID not found in the assertion of the Response', $e->getMessage());
        }

        $xml5 = file_get_contents(TEST_ROOT . '/data/responses/wrong_spnamequalifier.xml.base64');
        $this->assertSame(
            [
                'Value' => "492882615acf31c8096b627245d76ae53036c090",
                'Format' => Constants::NAMEID_EMAIL_ADDRESS,
                'SPNameQualifier' => "https://pitbulk.no-ip.org/newonelogin/demo1/metadata.php",
            ],
            (new Response($settings, $xml5))->getNameIdData()
        );

        $xml6 = file_get_contents(TEST_ROOT . '/data/responses/invalids/empty_nameid.xml.base64');
        $this->assertSame(
            [
                'Value' => "",
                'Format' => Constants::NAMEID_EMAIL_ADDRESS,
                'SPNameQualifier' => "http://stuff.com/endpoints/metadata.php",
            ],
            (new Response($settings, $xml6))->getNameIdData()
        );

        $settingsInfo['strict'] = true;
        $settings = new Settings($settingsInfo);

        try {
            (new Response($settings, $xml5))->getNameIdData();
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertContains('The SPNameQualifier value mismatch the SP entityID value.', $e->getMessage());
        }

        try {
            (new Response($settings, $xml6))->getNameIdData();
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertContains('An empty NameID value found', $e->getMessage());
        }
    }

    /**
     * @covers OneLogin\Saml2\Response::checkStatus
     */
    public function testCheckStatus()
    {
        (new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/response1.xml.base64')))->checkStatus();

        (new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64')))->checkStatus();

        try {
            (new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/invalids/status_code_responder.xml.base64')))->checkStatus();
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertContains('The status code of the Response was not Success, was Responder', $e->getMessage());
        }

        try {
            (new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/invalids/status_code_responer_and_msg.xml.base64')))->checkStatus();
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertContains('The status code of the Response was not Success, was Responder -> something_is_wrong', $e->getMessage());
        }
    }

    public function testQueryAssertions()
    {
        $this->assertSame(
            ['http://login.example.com/issuer' => true],
            (new Response(
                $this->settings,
                file_get_contents(TEST_ROOT . '/data/responses/adfs_response.xml.base64')
            ))->getIssuers()
        );

        $this->assertSame(
            ['http://idp.example.com/' => true],
            (new Response(
                $this->settings,
                file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64')
            ))->getIssuers()
        );

        $this->assertSame(
            ['https://pitbulk.no-ip.org/simplesaml/saml2/idp/metadata.php' => true, 'http://idp.example.com/' => true],
            (new Response(
                $this->settings,
                file_get_contents(TEST_ROOT . '/data/responses/double_signed_encrypted_assertion.xml.base64')
            ))->getIssuers()
        );

        $this->assertSame(
            ['https://pitbulk.no-ip.org/simplesaml/saml2/idp/metadata.php' => true],
            (new Response(
                $this->settings,
                file_get_contents(TEST_ROOT . '/data/responses/double_signed_response.xml.base64')
            ))->getIssuers()
        );

        $this->assertSame(
            ['https://pitbulk.no-ip.org/simplesaml/saml2/idp/metadata.php' => true, 'http://idp.example.com/' => true],
            (new Response(
                $this->settings,
                file_get_contents(TEST_ROOT . '/data/responses/signed_message_encrypted_assertion.xml.base64')
            ))->getIssuers()
        );

        $this->assertSame(
            ['https://pitbulk.no-ip.org/simplesaml/saml2/idp/metadata.php' => true],
            (new Response(
                $this->settings,
                file_get_contents(TEST_ROOT . '/data/responses/signed_assertion_response.xml.base64')
            ))->getIssuers()
        );

        $this->assertSame(
            ['http://idp.example.com/' => true],
            (new Response(
                $this->settings,
                file_get_contents(TEST_ROOT . '/data/responses/signed_encrypted_assertion.xml.base64')
            ))->getIssuers()
        );
    }

    /**
     * @covers OneLogin\Saml2\Response::getIssuers
     */
    public function testGetIssuers()
    {
        $this->assertSame(
            ['http://login.example.com/issuer' => true],
            (new Response(
                $this->settings,
                file_get_contents(TEST_ROOT . '/data/responses/adfs_response.xml.base64')
            ))->getIssuers()
        );

        $this->assertSame(
            ['http://idp.example.com/' => true],
            (new Response(
                $this->settings,
                file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64')
            ))->getIssuers()
        );

        $this->assertSame(
            ['https://pitbulk.no-ip.org/simplesaml/saml2/idp/metadata.php' => true, 'http://idp.example.com/' => true],
            (new Response(
                $this->settings,
                file_get_contents(TEST_ROOT . '/data/responses/double_signed_encrypted_assertion.xml.base64')
            ))->getIssuers()
        );

        $response4 = new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/invalids/no_issuer_response.xml.base64'));
        $response4->getIssuers();
        $this->assertSame(['http://idp.example.com/' => true], $response4->getIssuers());

        try {
            (new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/invalids/no_issuer_assertion.xml.base64')))->getIssuers();
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertContains('Issuer of the Assertion not found or multiple.', $e->getMessage());
        }
    }

    /**
     * @covers OneLogin\Saml2\Response::getSessionIndex
     */
    public function testGetSessionIndex()
    {
        $this->assertSame(
            '_531c32d283bdff7e04e487bcdbc4dd8d',
            (new Response(
                $this->settings,
                file_get_contents(TEST_ROOT . '/data/responses/response1.xml.base64')
            ))->getSessionIndex()
        );

        $this->assertSame(
            '_7164a9a9f97828bfdb8d0ebc004a05d2e7d873f70c',
            (new Response(
                $this->settings,
                file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64')
            ))->getSessionIndex()
        );
    }

    /**
     * @covers OneLogin\Saml2\Response::getAttributes
     */
    public function testGetAttributes()
    {
        $this->assertSame(
            [
                'uid' => ['demo'],
                'another_value' => ['value'],
            ],
            (new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/response1.xml.base64')))->getAttributes()
        );

        // An assertion that has no attributes should return an empty array when asked for the attributes
        $this->assertEmpty((new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/response2.xml.base64')))->getAttributes());

        // Encrypted Attributes are not supported
        $this->assertEmpty(
            (new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/invalids/encrypted_attrs.xml.base64')))->getAttributes()
        );

        // Duplicated Attribute names
        try {
            (new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/invalids/duplicated_attributes.xml.base64')))->getAttributes();
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertContains('Found an Attribute element with duplicated Name', $e->getMessage());
        }
    }

    /**
     * @covers OneLogin\Saml2\Response::getAttributesWithFriendlyName
     */
    public function testGetAttributesWithFriendlyName()
    {
        $this->assertSame(
            [
                'uid' => ['demo'],
                'givenName' => ['value'],
            ],
            (new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/response6.xml.base64')))->getAttributesWithFriendlyName()
        );
        // An assertion that has no attributes should return an empty array when asked for the attributes
        $this->assertEmpty(
            (new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/response2.xml.base64')))->getAttributesWithFriendlyName()
        );
        // Encrypted Attributes are not supported
        $this->assertEmpty(
            (new Response(
                $this->settings,
                file_get_contents(TEST_ROOT . '/data/responses/invalids/encrypted_attrs.xml.base64')
            ))->getAttributesWithFriendlyName()
        );
        // Duplicated Attribute names
        try {
            (
                new Response(
                    $this->settings,
                    file_get_contents(TEST_ROOT . '/data/responses/invalids/duplicated_attributes_with_friendly_names.xml.base64')
                )
            )->getAttributesWithFriendlyName();
            $this->fail('OneLogin\Saml2\ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertContains('Found an Attribute element with duplicated FriendlyName', $e->getMessage());
        }
    }

    /**
     * The Assertion is unsigned, the response is invalid but is able to retrieve the NameID
     *
     * @covers OneLogin\Saml2\Response::getNameId
     */
    public function testOnlyRetrieveAssertionWithIDThatMatchesSignatureReference()
    {
        $response = new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/wrapped_response_2.xml.base64'));

        $this->assertFalse($response->isValid());
        $this->assertSame('root@example.com', $response->getNameId());
    }

    /**
     * @covers OneLogin\Saml2\Response::getErrorException
     */
    public function testGetErrorException()
    {
        $response = new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/response4.xml.base64'));

        $this->assertFalse($response->isValid());
        $this->assertSame('SAML Response must contain 1 assertion', $response->getErrorException()->getMessage());

        $this->assertTrue((new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/valid_response.xml.base64')))->isValid());
    }

    /**
     * @covers OneLogin\Saml2\Response::getErrorException
     * @expectedException TypeError
     */
    public function testGetErrorExceptionNoException()
    {
        $this->assertNull((new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/response4.xml.base64')))->getErrorException());
    }

    /**
     * Test that the SignatureWrappingAttack is not allowed
     *
     * @covers OneLogin\Saml2\Response::getNameId
     */
    public function testDoesNotAllowSignatureWrappingAttack()
    {
        $response = new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/response4.xml.base64'));

        $this->assertSame('test@onelogin.com', $response->getNameId());

        $this->assertFalse($response->isValid());

        $this->assertSame('SAML Response must contain 1 assertion', $response->getErrorException()->getMessage());
    }

    public function testDoesNotAllowSignatureWrappingAttack2()
    {
        include TEST_ROOT . '/settings/settings1.php';

        unset($settingsInfo['idp']['x509cert']);
        $settingsInfo['strict'] = false;
        $settingsInfo['idp']['certFingerprint'] = "385b1eec71143f00db6af936e2ea12a28771d72c";
        $settingsInfo['sp']['privateKey'] = 'MIICXAIBAAKBgQDo6m+QZvYQ/xL0ElLgupK1QDcYL4f5PckwsNgS9pUvV7fzTqCHk8ThLxTk42MQ2McJsOeUJVP728KhymjFCqxgP4VuwRk9rpAl0+mhy6MPdyjyA6G14jrDWS65ysLchK4t/vwpEDz0SQlEoG1kMzllSm7zZS3XregA7DjNaUYQqwIDAQABAoGBALGR6bRBit+yV5TUU3MZSrf8WQSLWDLgs/33FQSAEYSib4+DJke2lKbI6jkGUoSJgFUXFbaQLtMY2+3VDsMKPBdAge9gIdvbkC4yoKjLGm/FBDOxxZcfLpR+9OPqU3qM9D0CNuliBWI7Je+p/zs09HIYucpDXy9E18KA1KNF6rfhAkEA9KoNam6wAKnmvMzz31ws3RuIOUeo2rx6aaVY95+P9tTxd6U+pNkwxy1aCGP+InVSwlYNA1aQ4Axi/GdMIWMkxwJBAPO1CP7cQNZQmu7yusY+GUObDII5YK9WLaY4RAicn5378crPBFxvUkqf9G6FHo7u88iTCIp+vwa3Hn9Tumg3iP0CQQDgUXWBasCVqzCxU5wY4tMDWjXYhpoLCpmVeRML3dDJt004rFm2HKe7Rhpw7PTZNQZOxUSjFeA4e0LaNf838UWLAkB8QfbHM3ffjhOg96PhhjINdVWoZCb230LBOHj/xxPfUmFTHcBEfQIBSJMxcrBFAnLL9qPpMXymqOFk3ETz9DTlAj8E0qGbp78aVbTOtuwEwNJII+RPw+Zkc+lKR+yaWkAzfIXw527NPHH3+rnBG72wyZr9ud4LAum9jh+5No1LQpk=';
        $settingsInfo['sp']['x509cert'] = 'MIICGzCCAYQCCQCNNcQXom32VDANBgkqhkiG9w0BAQUFADBSMQswCQYDVQQGEwJVUzELMAkGA1UECBMCSU4xFTATBgNVBAcTDEluZGlhbmFwb2xpczERMA8GA1UEChMIT25lTG9naW4xDDAKBgNVBAsTA0VuZzAeFw0xNDA0MjMxODQxMDFaFw0xNTA0MjMxODQxMDFaMFIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJJTjEVMBMGA1UEBxMMSW5kaWFuYXBvbGlzMREwDwYDVQQKEwhPbmVMb2dpbjEMMAoGA1UECxMDRW5nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDo6m+QZvYQ/xL0ElLgupK1QDcYL4f5PckwsNgS9pUvV7fzTqCHk8ThLxTk42MQ2McJsOeUJVP728KhymjFCqxgP4VuwRk9rpAl0+mhy6MPdyjyA6G14jrDWS65ysLchK4t/vwpEDz0SQlEoG1kMzllSm7zZS3XregA7DjNaUYQqwIDAQABMA0GCSqGSIb3DQEBBQUAA4GBALM2vGCiQ/vm+a6v40+VX2zdqHA2Q/1vF1ibQzJ54MJCOVWvs+vQXfZFhdm0OPM2IrDU7oqvKPqP6xOAeJK6H0yP7M4YL3fatSvIYmmfyXC9kt3Svz/NyrHzPhUnJ0ye/sUSXxnzQxwcm/9PwAqrQaA3QpQkH57ybF/OoryPe+2h';

        $this->assertFalse(
            (new Response(new Settings($settingsInfo), file_get_contents(TEST_ROOT . '/data/responses/wrapped_response_3.xml.base64')))->isValid()
        );
    }

    /**
     * Test that the node text with comment attack (VU#475445)
     * is not allowed
     *
     * @covers OneLogin\Saml2\Response::getNameId
     * @covers OneLogin\Saml2\Response::getAttributes
     */
    public function testNodeTextAttack()
    {
        $response = new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/response_node_text_attack.xml.base64'));
        $attributes = $response->getAttributes();
        $this->assertSame("support@onelogin.com", $response->getNameId());
        $this->assertSame("smith", $attributes['surname'][0]);
    }

    /**
     * @covers OneLogin\Saml2\Response::getSessionNotOnOrAfter
     */
    public function testGetSessionNotOnOrAfter()
    {
        $this->assertSame(
            1290203857,
            (new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/response1.xml.base64')))->getSessionNotOnOrAfter()
        );

        // An assertion that do not specified Session timeout should return NULL
        $this->assertNull((new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/response2.xml.base64')))->getSessionNotOnOrAfter());

        $this->assertSame(
            2696012228,
            (new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64')))->getSessionNotOnOrAfter()
        );
    }

    /**
     * @covers OneLogin\Saml2\Response::validateTimestamps
     */
    public function testValidateTimestamps()
    {
        (new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/valid_response.xml.base64')))->validateTimestamps();

        (new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64')))->validateTimestamps();

        try {
            (new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/expired_response.xml.base64')))->validateTimestamps();
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertSame('Could not validate timestamp: expired. Check system clock.', $e->getMessage());
        }

        try {
            (new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/invalids/not_after_failed.xml.base64')))->validateTimestamps();
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertSame('Could not validate timestamp: expired. Check system clock.', $e->getMessage());
        }

        try {
            (new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/invalids/not_before_failed.xml.base64')))->validateTimestamps();
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertSame('Could not validate timestamp: not yet valid. Check system clock.', $e->getMessage());
        }
    }

    /**
     * Case invalid version
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testValidateVersion()
    {
        $response = new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/invalids/no_saml2.xml.base64'));

        $this->assertFalse($response->isValid());
        $this->assertSame('Unsupported SAML version', $response->getErrorException()->getMessage());
    }

    /**
     * Case invalid no ID
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testValidateID()
    {
        $response = new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/invalids/no_id.xml.base64'));

        $this->assertFalse($response->isValid());
        $this->assertSame('Missing ID attribute on SAML Response', $response->getErrorException()->getMessage());
    }

    /**
     * Case invalid reference
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsInValidReference()
    {
        $response = new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/response1.xml.base64'));

        $this->assertFalse($response->isValid());
        $this->assertSame('Reference validation failed', $response->getErrorException()->getMessage());
    }

    /**
     * Case expired response
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsInValidExpired()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/expired_response.xml.base64');
        $this->assertTrue((new Response($this->settings, $xml))->isValid());

        $this->settings->setStrict(true);
        $response2 = new Response($this->settings, $xml);

        $this->assertFalse($response2->isValid());
        $this->assertSame('Could not validate timestamp: expired. Check system clock.', $response2->getErrorException()->getMessage());
    }

    /**
     * Case no key
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsInValidNoKey()
    {
        $response = new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/invalids/no_key.xml.base64'));

        $this->assertFalse($response->isValid());
        $this->assertSame('We have no idea about the key', $response->getErrorException()->getMessage());
    }

    /**
     * Case invalid multiple assertions
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsInValidMultipleAssertions()
    {
        $response = new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/invalids/multiple_assertions.xml.base64'));

        $this->assertFalse($response->isValid());
        $this->assertSame('SAML Response must contain 1 assertion', $response->getErrorException()->getMessage());
    }

    /**
     * Case invalid Encrypted Attrs
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsInValidEncAttrs()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/invalids/encrypted_attrs.xml.base64');
        $response = new Response($this->settings, $xml);

        $this->assertFalse($response->isValid());
        $this->assertSame('No Signature found. SAML Response rejected', $response->getErrorException()->getMessage());

        $this->settings->setStrict(true);
        $response2 = new Response($this->settings, $xml);

        $this->assertFalse($response2->isValid());
        $this->assertSame('There is an EncryptedAttribute in the Response and this SP not support them', $response2->getErrorException()->getMessage());
    }

    /**
     * Case invalid xml
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsInValidWrongXML()
    {
        include TEST_ROOT . '/settings/settings1.php';

        $settingsInfo['security']['wantXMLValidation'] = false;

        $settings = new Settings($settingsInfo);
        $settings->setStrict(false);

        $xml = file_get_contents(TEST_ROOT . '/data/responses/invalids/invalid_xml.xml.base64');
        $this->assertTrue((new Response($settings, $xml))->isValid());

        $settings->setStrict(true);
        $response2 = new Response($settings, $xml);
        $response2->isValid();
        $this->assertNotEquals('Invalid SAML Response. Not match the saml-schema-protocol-2.0.xsd', $response2->getErrorException()->getMessage());

        $settingsInfo['security']['wantXMLValidation'] = true;
        $settings2 = new Settings($settingsInfo);
        $settings2->setStrict(false);
        $response3 = new Response($settings2, $xml);
        $this->assertTrue($response3->isValid());

        $settings2->setStrict(true);
        $response4 = new Response($settings2, $xml);
        $this->assertFalse($response4->isValid());
        $this->assertSame('Invalid SAML Response. Not match the saml-schema-protocol-2.0.xsd', $response4->getErrorException()->getMessage());
    }

    /**
     * Case Invalid Response, Invalid Destination
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsInValidDestination()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/unsigned_response.xml.base64');

        $response = new Response($this->settings, $xml);
        $response->isValid();
        $this->assertSame('No Signature found. SAML Response rejected', $response->getErrorException()->getMessage());

        $this->settings->setStrict(true);
        $response2 = new Response($this->settings, $xml);

        $this->assertFalse($response2->isValid());
        $this->assertContains('The response was received at', $response2->getErrorException()->getMessage());

        // Empty Destination
        $xml2 = file_get_contents(TEST_ROOT . '/data/responses/invalids/empty_destination.xml.base64');
        $response3 = new Response($this->settings, $xml2);

        $this->assertFalse($response3->isValid());
        $this->assertSame('The response has an empty Destination value', $response3->getErrorException()->getMessage());

        include TEST_ROOT . '/settings/settings1.php';
        $settingsInfo['security']['relaxDestinationValidation'] = true;
        $this->assertTrue((new Response(new Settings($settingsInfo), $xml2))->isValid());
    }

    /**
     * Case Invalid Response, Invalid Audience
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsInValidAudience()
    {
        $message = base64_encode(
            str_replace(
                'http://stuff.com/endpoints/endpoints/acs.php',
                Utils::getSelfURLNoQuery(),
                base64_decode(file_get_contents(TEST_ROOT . '/data/responses/invalids/invalid_audience.xml.base64'))
            )
        );

        $response = new Response($this->settings, $message);
        $response->isValid();
        $this->assertSame('No Signature found. SAML Response rejected', $response->getErrorException()->getMessage());

        $this->settings->setStrict(true);
        $response2 = new Response($this->settings, $message);

        $this->assertFalse($response2->isValid());
        $this->assertSame(
            'Invalid audience for this Response (expected \'http://stuff.com/endpoints/metadata.php\', got \'http://invalid.audience.com\')',
            $response2->getErrorException()->getMessage()
        );
    }

    /**
     * Case Invalid Response, Invalid Issuer
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsInValidIssuer()
    {
        $currentURL = Utils::getSelfURLNoQuery();

        $message = base64_encode(
            str_replace(
                'http://stuff.com/endpoints/endpoints/acs.php',
                $currentURL,
                base64_decode(file_get_contents(TEST_ROOT . '/data/responses/invalids/invalid_issuer_assertion.xml.base64'))
            )
        );
        $message2 = base64_encode(
            str_replace(
                'http://stuff.com/endpoints/endpoints/acs.php',
                $currentURL,
                base64_decode(file_get_contents(TEST_ROOT . '/data/responses/invalids/invalid_issuer_message.xml.base64'))
            )
        );

        $response = new Response($this->settings, $message);
        $response->isValid();
        $this->assertSame('No Signature found. SAML Response rejected', $response->getErrorException()->getMessage());

        $response2 = new Response($this->settings, $message2);
        $response2->isValid();
        $this->assertSame('No Signature found. SAML Response rejected', $response2->getErrorException()->getMessage());

        $this->settings->setStrict(true);
        $response3 = new Response($this->settings, $message);

        $this->assertFalse($response3->isValid());
        $this->assertSame(
            'Invalid issuer in the Assertion/Response (expected \'http://idp.example.com/\', got \'http://invalid.issuer.example.com/\')',
            $response3->getErrorException()->getMessage()
        );

        $response4 = new Response($this->settings, $message2);

        $this->assertFalse($response4->isValid());
        $this->assertSame(
            'Invalid issuer in the Assertion/Response (expected \'http://idp.example.com/\', got \'http://invalid.isser.example.com/\')',
            $response4->getErrorException()->getMessage()
        );
    }

    /**
     * Case Invalid Response, Invalid SessionIndex
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsInValidSessionIndex()
    {
        $message = base64_encode(
            str_replace(
                'http://stuff.com/endpoints/endpoints/acs.php',
                Utils::getSelfURLNoQuery(),
                base64_decode(file_get_contents(TEST_ROOT . '/data/responses/invalids/invalid_sessionindex.xml.base64'))
            )
        );

        $response = new Response($this->settings, $message);
        $response->isValid();
        $this->assertSame('No Signature found. SAML Response rejected', $response->getErrorException()->getMessage());

        $this->settings->setStrict(true);
        $response2 = new Response($this->settings, $message);

        $this->assertFalse($response2->isValid());
        $this->assertSame('The attributes have expired, based on the SessionNotOnOrAfter of the AttributeStatement of this Response', $response2->getErrorException()->getMessage());
    }

    /**
     * Case Invalid Response, Invalid SubjectConfirmation
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsInValidSubjectConfirmation()
    {
        $currentURL = Utils::getSelfURLNoQuery();

        $message = base64_encode(str_replace('http://stuff.com/endpoints/endpoints/acs.php', $currentURL, base64_decode(file_get_contents(TEST_ROOT . '/data/responses/invalids/no_subjectconfirmation_method.xml.base64'))));
        $message2 = base64_encode(str_replace('http://stuff.com/endpoints/endpoints/acs.php', $currentURL, base64_decode(file_get_contents(TEST_ROOT . '/data/responses/invalids/no_subjectconfirmation_data.xml.base64'))));
        $message3 = base64_encode(str_replace('http://stuff.com/endpoints/endpoints/acs.php', $currentURL, base64_decode(file_get_contents(TEST_ROOT . '/data/responses/invalids/invalid_subjectconfirmation_inresponse.xml.base64'))));
        $message4 = base64_encode(str_replace('http://stuff.com/endpoints/endpoints/acs.php', $currentURL, base64_decode(file_get_contents(TEST_ROOT . '/data/responses/invalids/invalid_subjectconfirmation_recipient.xml.base64'))));
        $message5 = base64_encode(str_replace('http://stuff.com/endpoints/endpoints/acs.php', $currentURL, base64_decode(file_get_contents(TEST_ROOT . '/data/responses/invalids/invalid_subjectconfirmation_noa.xml.base64'))));
        $message6 = base64_encode(str_replace('http://stuff.com/endpoints/endpoints/acs.php', $currentURL, base64_decode(file_get_contents(TEST_ROOT . '/data/responses/invalids/invalid_subjectconfirmation_nb.xml.base64'))));

        $response = new Response($this->settings, $message);
        $response->isValid();
        $this->assertSame('No Signature found. SAML Response rejected', $response->getErrorException()->getMessage());

        $response2 = new Response($this->settings, $message2);
        $response2->isValid();
        $this->assertSame('No Signature found. SAML Response rejected', $response2->getErrorException()->getMessage());

        $response3 = new Response($this->settings, $message3);
        $response3->isValid();
        $this->assertSame('No Signature found. SAML Response rejected', $response3->getErrorException()->getMessage());

        $response4 = new Response($this->settings, $message4);
        $response4->isValid();
        $this->assertSame('No Signature found. SAML Response rejected', $response4->getErrorException()->getMessage());

        $response5 = new Response($this->settings, $message5);
        $response5->isValid();
        $this->assertSame('No Signature found. SAML Response rejected', $response5->getErrorException()->getMessage());

        $response6 = new Response($this->settings, $message6);
        $response6->isValid();
        $this->assertSame('No Signature found. SAML Response rejected', $response6->getErrorException()->getMessage());

        $this->settings->setStrict(true);

        $response = new Response($this->settings, $message);
        $this->assertFalse($response->isValid());
        $this->assertSame('A valid SubjectConfirmation was not found on this Response', $response->getErrorException()->getMessage());

        $response2 = new Response($this->settings, $message2);
        $this->assertFalse($response2->isValid());
        $this->assertSame('A valid SubjectConfirmation was not found on this Response', $response2->getErrorException()->getMessage());

        $response3 = new Response($this->settings, $message3);
        $this->assertFalse($response3->isValid());
        $this->assertSame('A valid SubjectConfirmation was not found on this Response', $response3->getErrorException()->getMessage());

        $response4 = new Response($this->settings, $message4);
        $this->assertFalse($response4->isValid());
        $this->assertSame('A valid SubjectConfirmation was not found on this Response', $response4->getErrorException()->getMessage());

        $response5 = new Response($this->settings, $message5);
        $this->assertFalse($response5->isValid());
        $this->assertSame('A valid SubjectConfirmation was not found on this Response', $response5->getErrorException()->getMessage());

        $response6 = new Response($this->settings, $message6);

        $this->assertFalse($response6->isValid());
        $this->assertSame('A valid SubjectConfirmation was not found on this Response', $response6->getErrorException()->getMessage());
    }

    /**
     * Somtimes IdPs uses datetimes with miliseconds, this
     * test is to verify that the toolkit supports them
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testDatetimeWithMiliseconds()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/unsigned_response_with_miliseconds.xm.base64');
        $response = new Response($this->settings, $xml);
        $response->isValid();
        $this->assertSame('No Signature found. SAML Response rejected', $response->getErrorException()->getMessage());

        $this->settings->setStrict(true);

        $response2 = new Response(
            $this->settings,
            base64_encode(str_replace('http://stuff.com/endpoints/endpoints/acs.php', Utils::getSelfURLNoQuery(), base64_decode($xml)))
        );

        $response2->isValid();
        $this->assertSame('No Signature found. SAML Response rejected', $response2->getErrorException()->getMessage());
    }

    /**
     * Case Invalid Response, Invalid requestID
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsInValidRequestId()
    {
        $message = base64_encode(
            str_replace(
                'http://stuff.com/endpoints/endpoints/acs.php',
                Utils::getSelfURLNoQuery(),
                base64_decode(file_get_contents(TEST_ROOT . '/data/responses/unsigned_response.xml.base64'))
            )
        );

        $response = new Response($this->settings, $message);

        $requestId = 'invalid';
        $response->isValid($requestId);
        $this->assertSame('No Signature found. SAML Response rejected', $response->getErrorException()->getMessage());

        $this->settings->setStrict(true);

        $response2 = new Response($this->settings, $message);
        $response2->isValid($requestId);
        $this->assertContains('The InResponseTo of the Response', $response2->getErrorException()->getMessage());

        $response2->isValid('_57bcbf70-7b1f-012e-c821-782bcb13bb38');
        $this->assertContains('No Signature found. SAML Response rejected', $response2->getErrorException()->getMessage());
    }

    /**
     * Case Invalid Response, Invalid signing issues
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsInValidSignIssues()
    {
        $message = base64_encode(
            str_replace(
                'http://stuff.com/endpoints/endpoints/acs.php',
                Utils::getSelfURLNoQuery(),
                base64_decode(file_get_contents(TEST_ROOT . '/data/responses/unsigned_response.xml.base64'))
            )
        );

        include TEST_ROOT . '/settings/settings1.php';

        $settingsInfo['security']['wantAssertionsSigned'] = false;
        $response = new Response(new Settings($settingsInfo), $message);
        $response->isValid();
        $this->assertContains('No Signature found. SAML Response rejected', $response->getErrorException()->getMessage());

        $settingsInfo['security']['wantAssertionsSigned'] = true;
        $response2 = new Response(new Settings($settingsInfo), $message);
        $response2->isValid();
        $this->assertContains('No Signature found. SAML Response rejected', $response2->getErrorException()->getMessage());

        $settingsInfo['strict'] = true;
        $settingsInfo['security']['wantAssertionsSigned'] = false;
        $response3 = new Response(new Settings($settingsInfo), $message);
        $response3->isValid();
        $this->assertContains('No Signature found. SAML Response rejected', $response3->getErrorException()->getMessage());

        $settingsInfo['security']['wantAssertionsSigned'] = true;
        $response4 = new Response(new Settings($settingsInfo), $message);

        $this->assertFalse($response4->isValid());
        $this->assertSame('The Assertion of the Response is not signed and the SP requires it', $response4->getErrorException()->getMessage());

        $settingsInfo['security']['wantAssertionsSigned'] = false;
        $settingsInfo['strict'] = false;

        $settingsInfo['security']['wantMessagesSigned'] = false;
        $response5 = new Response(new Settings($settingsInfo), $message);
        $response5->isValid();
        $this->assertContains('No Signature found. SAML Response rejected', $response5->getErrorException()->getMessage());

        $settingsInfo['security']['wantMessagesSigned'] = true;
        $response6 = new Response(new Settings($settingsInfo), $message);
        $response6->isValid();
        $this->assertContains('No Signature found. SAML Response rejected', $response6->getErrorException()->getMessage());

        $settingsInfo['strict'] = true;
        $settingsInfo['security']['wantMessagesSigned'] = false;
        $response7 = new Response(new Settings($settingsInfo), $message);
        $response7->isValid();
        $this->assertContains('No Signature found. SAML Response rejected', $response7->getErrorException()->getMessage());

        $settingsInfo['security']['wantMessagesSigned'] = true;
        $response8 = new Response(new Settings($settingsInfo), $message);

        $this->assertFalse($response8->isValid());
        $this->assertSame('The Message of the Response is not signed and the SP requires it', $response8->getErrorException()->getMessage());
    }

    /**
     * Case Invalid Response, Invalid encryptation issues
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsInValidEncIssues()
    {
        $message = base64_encode(
            str_replace(
                'http://stuff.com/endpoints/endpoints/acs.php',
                Utils::getSelfURLNoQuery(),
                base64_decode(file_get_contents(TEST_ROOT . '/data/responses/unsigned_response.xml.base64'))
            )
        );

        include TEST_ROOT . '/settings/settings1.php';

        $settingsInfo['security']['wantAssertionsEncrypted'] = true;
        $response = new Response(new Settings($settingsInfo), $message);
        $response->isValid();
        $this->assertContains('No Signature found. SAML Response rejected', $response->getErrorException()->getMessage());

        $settingsInfo['strict'] = true;
        $settingsInfo['security']['wantAssertionsEncrypted'] = false;
        $response2 = new Response(new Settings($settingsInfo), $message);
        $response2->isValid();
        $this->assertContains('No Signature found. SAML Response rejected', $response2->getErrorException()->getMessage());

        $settingsInfo['security']['wantAssertionsEncrypted'] = true;
        $response3 = new Response(new Settings($settingsInfo), $message);

        $this->assertFalse($response3->isValid());
        $this->assertSame('The assertion of the Response is not encrypted and the SP requires it', $response3->getErrorException()->getMessage());

        $settingsInfo['security']['wantAssertionsEncrypted'] = false;
        $settingsInfo['security']['wantNameIdEncrypted'] = true;
        $settingsInfo['strict'] = false;
        $response4 = new Response(new Settings($settingsInfo), $message);
        $response4->isValid();
        $this->assertContains('No Signature found. SAML Response rejected', $response4->getErrorException()->getMessage());

        $settingsInfo['strict'] = true;
        $response5 = new Response(new Settings($settingsInfo), $message);
        $this->assertFalse($response5->isValid());
        $this->assertSame('The NameID of the Response is not encrypted and the SP requires it', $response5->getErrorException()->getMessage());
    }

    /**
     * Case invalid cert
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsInValidCert()
    {
        include TEST_ROOT . '/settings/settings1.php';
        $settingsInfo['idp']['x509cert'] = 'NotValidCert';
        $response = new Response(new Settings($settingsInfo), file_get_contents(TEST_ROOT . '/data/responses/valid_response.xml.base64'));

        $this->assertFalse($response->isValid());
        $this->assertSame('openssl_x509_read(): supplied parameter cannot be coerced into an X509 certificate!', $response->getErrorException()->getMessage());
    }

    /**
     * Case invalid cert2
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsInValidCert2()
    {
        include TEST_ROOT . '/settings/settings1.php';
        $settingsInfo['idp']['x509cert'] = 'MIIENjCCAx6gAwIBAgIBATANBgkqhkiG9w0BAQUFADBvMQswCQYDVQQGEwJTRTEU MBIGA1UEChMLQWRkVHJ1c3QgQUIxJjAkBgNVBAsTHUFkZFRydXN0IEV4dGVybmFs IFRUUCBOZXR3b3JrMSIwIAYDVQQDExlBZGRUcnVzdCBFeHRlcm5hbCBDQSBSb290 MB4XDTAwMDUzMDEwNDgzOFoXDTIwMDUzMDEwNDgzOFowbzELMAkGA1UEBhMCU0Ux FDASBgNVBAoTC0FkZFRydXN0IEFCMSYwJAYDVQQLEx1BZGRUcnVzdCBFeHRlcm5h bCBUVFAgTmV0d29yazEiMCAGA1UEAxMZQWRkVHJ1c3QgRXh0ZXJuYWwgQ0EgUm9v dDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALf3GjPm8gAELTngTlvt H7xsD821+iO2zt6bETOXpClMfZOfvUq8k+0DGuOPz+VtUFrWlymUWoCwSXrbLpX9 uMq/NzgtHj6RQa1wVsfwTz/oMp50ysiQVOnGXw94nZpAPA6sYapeFI+eh6FqUNzX mk6vBbOmcZSccbNQYArHE504B4YCqOmoaSYYkKtMsE8jqzpPhNjfzp/haW+710LX a0Tkx63ubUFfclpxCDezeWWkWaCUN/cALw3CknLa0Dhy2xSoRcRdKn23tNbE7qzN E0S3ySvdQwAl+mG5aWpYIxG3pzOPVnVZ9c0p10a3CitlttNCbxWyuHv77+ldU9U0 WicCAwEAAaOB3DCB2TAdBgNVHQ4EFgQUrb2YejS0Jvf6xCZU7wO94CTLVBowCwYD VR0PBAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wgZkGA1UdIwSBkTCBjoAUrb2YejS0 Jvf6xCZU7wO94CTLVBqhc6RxMG8xCzAJBgNVBAYTAlNFMRQwEgYDVQQKEwtBZGRU cnVzdCBBQjEmMCQGA1UECxMdQWRkVHJ1c3QgRXh0ZXJuYWwgVFRQIE5ldHdvcmsx IjAgBgNVBAMTGUFkZFRydXN0IEV4dGVybmFsIENBIFJvb3SCAQEwDQYJKoZIhvcN AQEFBQADggEBALCb4IUlwtYj4g+WBpKdQZic2YR5gdkeWxQHIzZlj7DYd7usQWxH YINRsPkyPef89iYTx4AWpb9a/IfPeHmJIZriTAcKhjW88t5RxNKWt9x+Tu5w/Rw5 6wwCURQtjr0W4MHfRnXnJK3s9EK0hZNwEGe6nQY1ShjTK3rMUUKhemPR5ruhxSvC Nr4TDea9Y355e6cJDUCrat2PisP29owaQgVR1EX1n6diIWgVIEM8med8vSTYqZEX c4g/VhsxOBi0cQ+azcgOno4uG+GMmIPLHzHxREzGBHNJdmAPx/i9F4BrLunMTA5a mnkPIAou1Z5jJh5VkpTYghdae9C8x49OhgQ=';
        $response = new Response(new Settings($settingsInfo), file_get_contents(TEST_ROOT . '/data/responses/valid_response.xml.base64'));

        $this->assertFalse($response->isValid());
        $this->assertSame('Signature validation failed. SAML Response rejected', $response->getErrorException()->getMessage());
    }

    /**
     * Case response with different namespace
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testNamespaceIsValid()
    {
        $response = new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/response_namespaces.xml.base64'));

        $response->isValid();
        $this->assertContains('No Signature found. SAML Response rejected', $response->getErrorException()->getMessage());
    }

    /**
     * Case response from ADFS
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testADFSValid()
    {
        $response = new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/response_adfs1.xml.base64'));

        $response->isValid();
        $this->assertContains('No Signature found. SAML Response rejected', $response->getErrorException()->getMessage());
    }

    /**
     * Case valid response
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsValid()
    {
        $this->assertTrue((new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/valid_response.xml.base64')))->isValid());
    }

    /**
     * Case valid response2
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsValid2()
    {
        include TEST_ROOT . '/settings/settings1.php';
        $settingsInfo['idp']['certFingerprint'] = Utils::calculateX509Fingerprint(Utils::formatCert($settingsInfo['idp']['x509cert']));
        $settingsInfo['idp']['x509cert'] = null;

        $this->assertTrue((new Response(new Settings($settingsInfo), file_get_contents(TEST_ROOT . '/data/responses/valid_response.xml.base64')))->isValid());
    }

    /**
     * Case valid encrypted assertion
     *
     * Signed data can't be modified, so Destination will always fail in strict mode
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsValidEnc()
    {
        $this->assertTrue(
            (new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/double_signed_encrypted_assertion.xml.base64')))->isValid()
        );

        $this->assertTrue((new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/signed_encrypted_assertion.xml.base64')))->isValid());

        $this->assertTrue(
            (new Response($this->settings, file_get_contents(TEST_ROOT . '/data/responses/signed_message_encrypted_assertion.xml.base64')))->isValid()
        );

        include TEST_ROOT . '/settings/settings1.php';
        $settingsInfo['strict'] = true;
        // In order to avoid the destination problem
        $response4 = new Response(
            new Settings($settingsInfo),
            base64_encode(
                str_replace(
                    'http://stuff.com/endpoints/endpoints/acs.php',
                    Utils::getSelfURLNoQuery(),
                    base64_decode(file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64'))
                )
            )
        );

        $response4->isValid();
        $this->assertContains('No Signature found. SAML Response rejected', $response4->getErrorException()->getMessage());
    }

    /**
     * Case valid sign response / sign assertion / both signed
     *
     * Strict mode will always fail due destination problem, if we manipulate it
     * the sign will fail.
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsValidSign()
    {
        $xml = base64_encode(file_get_contents(TEST_ROOT . '/data/responses/signed_message_response.xml'));
        $this->assertTrue((new Response($this->settings, $xml))->isValid());

        $xml2 = file_get_contents(TEST_ROOT . '/data/responses/signed_assertion_response.xml.base64');
        $this->assertTrue((new Response($this->settings, $xml2))->isValid());

        $xml3 = file_get_contents(TEST_ROOT . '/data/responses/double_signed_response.xml.base64');
        $this->assertTrue((new Response($this->settings, $xml3))->isValid());

        $dom = new DOMDocument();
        $dom->loadXML(base64_decode($xml));
        $dom->firstChild->firstChild->nodeValue = 'https://example.com/other-idp';
        $response4 = new Response($this->settings, base64_encode($dom->saveXML()));
        $this->assertFalse($response4->isValid());
        $this->assertSame('Reference validation failed', $response4->getErrorException()->getMessage());

        $dom2 = new DOMDocument();
        $dom2->loadXML(base64_decode($xml2));
        $dom2->firstChild->firstChild->nodeValue = 'https://example.com/other-idp';
        $this->assertTrue((new Response($this->settings, base64_encode($dom2->saveXML())))->isValid());

        $dom3 = new DOMDocument();
        $dom3->loadXML(base64_decode($xml3));
        $dom3->firstChild->firstChild->nodeValue = 'https://example.com/other-idp';
        $response6 = new Response($this->settings, base64_encode($dom3->saveXML()));
        $this->assertFalse($response6->isValid());
        $this->assertSame('Reference validation failed', $response6->getErrorException()->getMessage());
    }

    public function testIsValidSignWithEmptyReferenceURI()
    {
        include TEST_ROOT . '/settings/settings1.php';

        $settingsInfo['idp']['x509cert'] = 'MIICGzCCAYQCCQCNNcQXom32VDANBgkqhkiG9w0BAQUFADBSMQswCQYDVQQGEwJVUzELMAkGA1UECBMCSU4xFTATBgNVBAcTDEluZGlhbmFwb2xpczERMA8GA1UEChMIT25lTG9naW4xDDAKBgNVBAsTA0VuZzAeFw0xNDA0MjMxODQxMDFaFw0xNTA0MjMxODQxMDFaMFIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJJTjEVMBMGA1UEBxMMSW5kaWFuYXBvbGlzMREwDwYDVQQKEwhPbmVMb2dpbjEMMAoGA1UECxMDRW5nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDo6m+QZvYQ/xL0ElLgupK1QDcYL4f5PckwsNgS9pUvV7fzTqCHk8ThLxTk42MQ2McJsOeUJVP728KhymjFCqxgP4VuwRk9rpAl0+mhy6MPdyjyA6G14jrDWS65ysLchK4t/vwpEDz0SQlEoG1kMzllSm7zZS3XregA7DjNaUYQqwIDAQABMA0GCSqGSIb3DQEBBQUAA4GBALM2vGCiQ/vm+a6v40+VX2zdqHA2Q/1vF1ibQzJ54MJCOVWvs+vQXfZFhdm0OPM2IrDU7oqvKPqP6xOAeJK6H0yP7M4YL3fatSvIYmmfyXC9kt3Svz/NyrHzPhUnJ0ye/sUSXxnzQxwcm/9PwAqrQaA3QpQkH57ybF/OoryPe+2h';
        $response = new Response(new Settings($settingsInfo), file_get_contents(TEST_ROOT . '/data/responses/response_without_reference_uri.xml.base64'));
        $this->assertTrue($response->isValid());
        $attributes = $response->getAttributes();
        $this->assertTrue(!empty($attributes));
        $this->assertSame('saml@user.com', $attributes['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'][0]);
    }

    /**
     * Case: Using x509certMulti
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsValidSignUsingX509certMulti()
    {
        include TEST_ROOT . '/settings/settings6.php';

        $this->assertTrue(
            (new Response(new Settings($settingsInfo), base64_encode(file_get_contents(TEST_ROOT . '/data/responses/signed_message_response.xml'))))->isValid()
        );
    }
}
