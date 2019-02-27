<?php

namespace Saml2\Tests;

use DOMDocument;
use Saml2\Constants;
use Saml2\Error;
use Saml2\LogoutRequest;
use Saml2\Settings;
use Saml2\Utils;
use Saml2\ValidationError;
use TypeError;

class LogoutRequestTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @var Settings
     */
    private $settings;


    public function setUp(): void
    {
        $this->settings = new Settings(require TEST_ROOT . '/settings/settings1.php');
    }

    /**
     * @covers \Saml2\LogoutRequest
     */
    public function testConstructor()
    {
        $settingsInfo = require TEST_ROOT . '/settings/settings1.php';

        $settingsInfo['security']['nameIdEncrypted'] = true;

        $logoutUrl = Utils::redirect(
            'http://idp.example.com/SingleLogoutService.php',
            ['SAMLRequest' => (new LogoutRequest(new Settings($settingsInfo)))->getRequest()],
            true
        );
        $this->assertRegExp('#^http://idp\.example\.com\/SingleLogoutService\.php\?SAMLRequest=#', $logoutUrl);
        parse_str(parse_url($logoutUrl, PHP_URL_QUERY), $exploded);
        // parse_url already urldecode de params so is not required.
        $inflated = gzinflate(base64_decode($exploded['SAMLRequest']));
        $this->assertRegExp('#^<samlp:LogoutRequest#', $inflated);
        $this->assertRegExp('#<saml:EncryptedID>#', $inflated);
    }

    /**
     * @covers \Saml2\LogoutRequest
     */
    public function testConstructorWithRequest()
    {
        $logoutUrl = Utils::redirect(
            'http://idp.example.com/SingleLogoutService.php',
            [
                'SAMLRequest' => (
                    new LogoutRequest(
                        new Settings(require TEST_ROOT . '/settings/settings1.php'),
                        file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request_deflated.xml.base64')
                    )
                )->getRequest(),
            ],
            true
        );
        $this->assertRegExp('#^http://idp\.example\.com\/SingleLogoutService\.php\?SAMLRequest=#', $logoutUrl);
        parse_str(parse_url($logoutUrl, PHP_URL_QUERY), $exploded);
        // parse_url already urldecode de params so is not required.
        $this->assertRegExp('#<samlp:LogoutRequest#', gzinflate(base64_decode($exploded['SAMLRequest'])));
    }

    /**
     * @covers \Saml2\LogoutRequest
     */
    public function testConstructorWithSessionIndex()
    {
        $sessionIndex = '_51be37965feb5579d803141076936dc2e9d1d98ebf';
        $logoutUrl = Utils::redirect(
            'http://idp.example.com/SingleLogoutService.php',
            ['SAMLRequest' => (new LogoutRequest(new Settings(require TEST_ROOT . '/settings/settings1.php'), null, null, $sessionIndex))->getRequest()],
            true
        );
        $this->assertRegExp('#^http://idp\.example\.com\/SingleLogoutService\.php\?SAMLRequest=#', $logoutUrl);
        parse_str(parse_url($logoutUrl, PHP_URL_QUERY), $exploded);
        // parse_url already urldecode de params so is not required.
        $inflated = gzinflate(base64_decode($exploded['SAMLRequest']));
        $this->assertRegExp('#^<samlp:LogoutRequest#', $inflated);

        $sessionIndexes = LogoutRequest::getSessionIndexes($inflated);
        $this->assertIsArray($sessionIndexes);
        $this->assertSame([$sessionIndex], $sessionIndexes);
    }

    /**
     * @covers \Saml2\LogoutRequest
     */
    public function testConstructorWithNameIdFormatOnParameter()
    {
        $nameId = 'test@example.com';
        $logoutUrl = Utils::redirect(
            'http://idp.example.com/SingleLogoutService.php',
            [
                'SAMLRequest' => (
                    new LogoutRequest(
                        new Settings(require TEST_ROOT . '/settings/settings1.php'),
                        null,
                        $nameId,
                        null,
                        Constants::NAMEID_TRANSIENT
                    )
                )->getRequest(),
            ],
            true
        );
        $this->assertRegExp('#^http://idp\.example\.com\/SingleLogoutService\.php\?SAMLRequest=#', $logoutUrl);
        parse_str(parse_url($logoutUrl, PHP_URL_QUERY), $exploded);
        // parse_url already urldecode de params so is not required.
        $inflated = gzinflate(base64_decode($exploded['SAMLRequest']));
        $this->assertRegExp('#^<samlp:LogoutRequest#', $inflated);

        $this->assertSame($nameId, LogoutRequest::getNameId($inflated));

        $logoutNameIdData = LogoutRequest::getNameIdData($inflated);
        $this->assertSame(Constants::NAMEID_TRANSIENT, $logoutNameIdData['Format']);
    }

    /**
     * @covers \Saml2\LogoutRequest
     */
    public function testConstructorWithNameIdFormatOnSettings()
    {
        $settingsInfo = require TEST_ROOT . '/settings/settings1.php';
        $nameId = 'test@example.com';
        $settingsInfo['sp']['NameIDFormat'] = Constants::NAMEID_TRANSIENT;
        $logoutUrl = Utils::redirect(
            'http://idp.example.com/SingleLogoutService.php',
            ['SAMLRequest' => (new LogoutRequest(new Settings($settingsInfo), null, $nameId, null, null))->getRequest()],
            true
        );
        $this->assertRegExp('#^http://idp\.example\.com\/SingleLogoutService\.php\?SAMLRequest=#', $logoutUrl);
        parse_str(parse_url($logoutUrl, PHP_URL_QUERY), $exploded);
        // parse_url already urldecode de params so is not required.
        $inflated = gzinflate(base64_decode($exploded['SAMLRequest']));
        $this->assertRegExp('#^<samlp:LogoutRequest#', $inflated);
        $this->assertSame($nameId, LogoutRequest::getNameId($inflated));
        $logoutNameIdData = LogoutRequest::getNameIdData($inflated);
        $this->assertSame(Constants::NAMEID_TRANSIENT, $logoutNameIdData['Format']);
    }

    /**
     * @covers \Saml2\LogoutRequest
     */
    public function testConstructorWithoutNameIdFormat()
    {
        $settingsInfo = require TEST_ROOT . '/settings/settings1.php';
        $nameId = 'test@example.com';
        $settingsInfo['sp']['NameIDFormat'] = Constants::NAMEID_UNSPECIFIED;
        $logoutUrl = Utils::redirect(
            'http://idp.example.com/SingleLogoutService.php',
            ['SAMLRequest' => (new LogoutRequest(new Settings($settingsInfo), null, $nameId, null, null))->getRequest()],
            true
        );
        $this->assertRegExp('#^http://idp\.example\.com\/SingleLogoutService\.php\?SAMLRequest=#', $logoutUrl);
        parse_str(parse_url($logoutUrl, PHP_URL_QUERY), $exploded);
        // parse_url already urldecode de params so is not required.
        $inflated = gzinflate(base64_decode($exploded['SAMLRequest']));
        $this->assertRegExp('#^<samlp:LogoutRequest#', $inflated);
        $this->assertSame($nameId, LogoutRequest::getNameId($inflated));
        $logoutNameIdData = LogoutRequest::getNameIdData($inflated);
        $this->assertFalse(isset($logoutNameIdData['Format']));
    }
    /**
     * @covers \Saml2\LogoutRequest
     */
    public function testConstructorWithNameIdNameQualifier()
    {
        $nameId = 'test@example.com';
        $nameIdNameQualifier = 'https://test.example.com/saml/metadata';
        $logoutUrl = Utils::redirect(
            'http://idp.example.com/SingleLogoutService.php',
            [
                'SAMLRequest' => (
                    new LogoutRequest(
                        new Settings(require TEST_ROOT . '/settings/settings1.php'),
                        null,
                        $nameId,
                        null,
                        Constants::NAMEID_TRANSIENT,
                        $nameIdNameQualifier
                    )
                )->getRequest(),
            ],
            true
        );
        $this->assertRegExp('#^http://idp\.example\.com\/SingleLogoutService\.php\?SAMLRequest=#', $logoutUrl);
        parse_str(parse_url($logoutUrl, PHP_URL_QUERY), $exploded);
        // parse_url already urldecode de params so is not required.
        $inflated = gzinflate(base64_decode($exploded['SAMLRequest']));
        $this->assertRegExp('#^<samlp:LogoutRequest#', $inflated);
        $this->assertSame($nameId, LogoutRequest::getNameId($inflated));
        $logoutNameIdData = LogoutRequest::getNameIdData($inflated);
        $this->assertSame(Constants::NAMEID_TRANSIENT, $logoutNameIdData['Format']);
        $this->assertSame($nameIdNameQualifier, $logoutNameIdData['NameQualifier']);
    }

    /**
     * The creation of a deflated SAML Logout Request
     *
     * @covers \Saml2\LogoutRequest
     */
    public function testCreateDeflatedSAMLLogoutRequestURLParameter()
    {
        $logoutUrl = Utils::redirect(
            'http://idp.example.com/SingleLogoutService.php',
            ['SAMLRequest' => (new LogoutRequest($this->settings))->getRequest()],
            true
        );
        $this->assertRegExp('#^http://idp\.example\.com\/SingleLogoutService\.php\?SAMLRequest=#', $logoutUrl);
        parse_str(parse_url($logoutUrl, PHP_URL_QUERY), $exploded);
        // parse_url already urldecode de params so is not required.
        $this->assertRegExp('#^<samlp:LogoutRequest#', gzinflate(base64_decode($exploded['SAMLRequest'])));
    }

    /**
     * Case: Able to generate encryptedID with MultiCert
     *
     * @covers \Saml2\LogoutRequest
     */
    public function testConstructorEncryptIdUsingX509certMulti()
    {
        $settingsInfo = require TEST_ROOT . '/settings/settings6.php';

        $settingsInfo['security']['nameIdEncrypted'] = true;

        $logoutUrl = Utils::redirect(
            'http://idp.example.com/SingleLogoutService.php',
            ['SAMLRequest' => (new LogoutRequest(new Settings($settingsInfo)))->getRequest()],
            true
        );
        $this->assertRegExp('#^http://idp\.example\.com\/SingleLogoutService\.php\?SAMLRequest=#', $logoutUrl);
        parse_str(parse_url($logoutUrl, PHP_URL_QUERY), $exploded);
        // parse_url already urldecode de params so is not required.
        $inflated = gzinflate(base64_decode($exploded['SAMLRequest']));
        $this->assertRegExp('#^<samlp:LogoutRequest#', $inflated);
        $this->assertRegExp('#<saml:EncryptedID>#', $inflated);
    }

    /**
     * @covers \Saml2\LogoutRequest::getID
     */
    public function testGetIDFromSAMLLogoutRequest()
    {
        $this->assertSame(
            'ONELOGIN_21584ccdfaca36a145ae990442dcd96bfe60151e',
            LogoutRequest::getID(
                file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request.xml')
            )
        );
    }

    /**
     * @covers \Saml2\LogoutRequest::getID
     */
    public function testGetIDFromDeflatedSAMLLogoutRequest()
    {
        $this->assertSame(
            'ONELOGIN_21584ccdfaca36a145ae990442dcd96bfe60151e',
            LogoutRequest::getID(
                gzinflate(
                    base64_decode(
                        file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request_deflated.xml.base64')
                    )
                )
            )
        );
    }

    /**
     * @covers \Saml2\LogoutRequest::getNameIdData
     */
    public function testGetNameIdData()
    {
        $this->assertSame(
            [
                'Value' => 'ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c',
                'Format' => Constants::NAMEID_UNSPECIFIED,
                'SPNameQualifier' => 'http://idp.example.com/',
            ],
            LogoutRequest::getNameIdData(file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request.xml'))
        );

        $request2 = file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request_encrypted_nameid.xml');

        try {
            LogoutRequest::getNameIdData($request2);
            $this->fail('Error was not raised');
        } catch (Error $e) {
            $this->assertStringContainsString('Key is required in order to decrypt the NameID', $e->getMessage());
        }

        $this->assertSame(
            [
                'Value' => 'ONELOGIN_9c86c4542ab9d6fce07f2f7fd335287b9b3cdf69',
                'Format' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress',
                'SPNameQualifier' => 'https://pitbulk.no-ip.org/newonelogin/demo1/metadata.php',
            ],
            LogoutRequest::getNameIdData($request2, $this->settings->getSPkey())
        );

        try {
            LogoutRequest::getNameIdData(file_get_contents(TEST_ROOT . '/data/logout_requests/invalids/no_nameId.xml'));
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertStringContainsString('NameID not found in the Logout Request', $e->getMessage());
        }

        $logoutRequestStr = (
            new LogoutRequest(
                $this->settings,
                null,
                "ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c",
                null,
                Constants::NAMEID_PERSISTENT,
                $this->settings->getIdPEntityId(),
                $this->settings->getSPEntityId()
            )
        )->getXML();
        $this->assertStringContainsString('ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c', $logoutRequestStr);
        $this->assertStringContainsString('Format="' . Constants::NAMEID_PERSISTENT, $logoutRequestStr);
        $this->assertStringContainsString('NameQualifier="' . $this->settings->getIdPEntityId(), $logoutRequestStr);
        $this->assertStringContainsString('SPNameQualifier="' . $this->settings->getSPEntityId(), $logoutRequestStr);

        $logoutRequestStr2 = (
            new LogoutRequest(
                $this->settings,
                null,
                "ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c",
                null,
                Constants::NAMEID_ENTITY,
                $this->settings->getIdPEntityId(),
                $this->settings->getSPEntityId()
            )
        )->getXML();
        $this->assertStringContainsString('ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c', $logoutRequestStr2);
        $this->assertStringContainsString('Format="' . Constants::NAMEID_ENTITY, $logoutRequestStr2);
        $this->assertStringNotContainsString('NameQualifier', $logoutRequestStr2);
        $this->assertStringNotContainsString('SPNameQualifier', $logoutRequestStr2);

        $logoutRequestStr3 = (
            new LogoutRequest(
                $this->settings,
                null,
                "ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c",
                null,
                Constants::NAMEID_UNSPECIFIED
            )
        )->getXML();
        $this->assertStringContainsString('ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c', $logoutRequestStr3);
        $this->assertStringNotContainsString('Format', $logoutRequestStr3);
        $this->assertStringNotContainsString('NameQualifier', $logoutRequestStr3);
        $this->assertStringNotContainsString('SPNameQualifier', $logoutRequestStr3);
    }

    /**
     * @covers \Saml2\LogoutRequest::getNameId
     */
    public function testGetNameId()
    {
        $this->assertSame(
            'ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c',
            LogoutRequest::getNameId(file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request.xml'))
        );

        $request2 = file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request_encrypted_nameid.xml');
        try {
            LogoutRequest::getNameId($request2);
            $this->fail('Error was not raised');
        } catch (Error $e) {
            $this->assertStringContainsString('Key is required in order to decrypt the NameID', $e->getMessage());
        }
        $this->assertSame('ONELOGIN_9c86c4542ab9d6fce07f2f7fd335287b9b3cdf69', LogoutRequest::getNameId($request2, $this->settings->getSPkey()));
    }

    /**
     * @covers \Saml2\LogoutRequest::getIssuer
     */
    public function testGetIssuer()
    {
        $dom = new DOMDocument();
        $dom->loadXML(file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request.xml'));
        $this->assertSame('http://idp.example.com/', LogoutRequest::getIssuer($dom));
    }

    /**
     * @covers \Saml2\LogoutRequest::getSessionIndexes
     */
    public function testGetSessionIndexes()
    {
        $this->assertEmpty(LogoutRequest::getSessionIndexes(file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request.xml')));

        $this->assertSame(
            ['_ac72a76526cb6ca19f8438e73879a0e6c8ae5131'],
            LogoutRequest::getSessionIndexes(file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request_with_sessionindex.xml'))
        );
    }

    /**
     * @covers \Saml2\LogoutRequest::getErrorException
     */
    public function testGetErrorException()
    {
        $encodedRequest = base64_encode(gzdeflate(file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request.xml')));

        $logoutRequest = new LogoutRequest($this->settings, $encodedRequest);

        $this->assertTrue($logoutRequest->isValid());

        $this->settings->setStrict(true);
        $logoutRequest2 = new LogoutRequest($this->settings, $encodedRequest);

        $this->assertFalse($logoutRequest2->isValid());
        $this->assertStringContainsString('The LogoutRequest was received at', $logoutRequest2->getErrorException()->getMessage());
    }

    /**
     * @covers \Saml2\LogoutRequest::getErrorException
     */
    public function testGetErrorExceptionNoException()
    {
        $this->expectException(TypeError::class);
        (
            new LogoutRequest(
                $this->settings,
                base64_encode(gzdeflate(file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request.xml')))
            )
        )->getErrorException();
    }

    /**
     * Case Invalid Issuer
     *
     * @covers \Saml2\LogoutRequest::isValid
     */
    public function testIsInvalidIssuer()
    {
        $encodedRequest = base64_encode(
            gzdeflate(
                str_replace(
                    'http://stuff.com/endpoints/endpoints/sls.php',
                    Utils::getSelfURLNoQuery(),
                    file_get_contents(TEST_ROOT . '/data/logout_requests/invalids/invalid_issuer.xml')
                )
            )
        );

        $this->assertTrue((new LogoutRequest($this->settings, $encodedRequest))->isValid());

        $this->settings->setStrict(true);
        $logoutRequest2 = new LogoutRequest($this->settings, $encodedRequest);

        $this->assertFalse($logoutRequest2->isValid());
        $this->assertStringContainsString('Invalid issuer in the Logout Request', $logoutRequest2->getErrorException()->getMessage());
    }

    /**
     * Case invalid xml
     *
     * @covers \Saml2\LogoutRequest::isValid
     */
    public function testIsInValidWrongXML()
    {
        $settingsInfo = require TEST_ROOT . '/settings/settings1.php';

        $settingsInfo['security']['wantXMLValidation'] = false;

        $settings = new Settings($settingsInfo);
        $settings->setStrict(false);

        $message = file_get_contents(TEST_ROOT . '/data/logout_requests/invalids/invalid_xml.xml.base64');
        $this->assertTrue((new LogoutRequest($settings, $message))->isValid());

        $settings->setStrict(true);
        $response2 = new LogoutRequest($settings, $message);
        $response2->isValid();
        $this->assertNotEquals('Invalid SAML Logout Request. Not match the saml-schema-protocol-2.0.xsd', $response2->getErrorException()->getMessage());

        $settingsInfo['security']['wantXMLValidation'] = true;
        $settings2 = new Settings($settingsInfo);
        $settings2->setStrict(false);
        $response3 = new LogoutRequest($settings2, $message);
        $this->assertTrue($response3->isValid());

        $settings2->setStrict(true);
        $response4 = new LogoutRequest($settings2, $message);
        $this->assertFalse($response4->isValid());
        $this->assertSame('Invalid SAML Logout Request. Not match the saml-schema-protocol-2.0.xsd', $response4->getErrorException()->getMessage());
    }

    /**
     * Case Invalid Destination
     *
     * @covers \Saml2\LogoutRequest::isValid
     */
    public function testIsInvalidDestination()
    {
        $encodedRequest = base64_encode(gzdeflate(file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request.xml')));

        $this->assertTrue((new LogoutRequest($this->settings, $encodedRequest))->isValid());

        $this->settings->setStrict(true);
        $logoutRequest2 = new LogoutRequest($this->settings, $encodedRequest);

        $this->assertFalse($logoutRequest2->isValid());
        $this->assertStringContainsString('The LogoutRequest was received at', $logoutRequest2->getErrorException()->getMessage());
    }

    /**
     * Case Invalid NotOnOrAfter
     *
     * @covers \Saml2\LogoutRequest::isValid
     */
    public function testIsInvalidNotOnOrAfter()
    {
        $encodedRequest = base64_encode(
            gzdeflate(
                str_replace(
                    'http://stuff.com/endpoints/endpoints/sls.php',
                    Utils::getSelfURLNoQuery(),
                    file_get_contents(TEST_ROOT . '/data/logout_requests/invalids/not_after_failed.xml')
                )
            )
        );

        $this->assertTrue((new LogoutRequest($this->settings, $encodedRequest))->isValid());

        $this->settings->setStrict(true);
        $logoutRequest2 = new LogoutRequest($this->settings, $encodedRequest);

        $this->assertFalse($logoutRequest2->isValid());
        $this->assertSame("Could not validate timestamp: expired. Check system clock.", $logoutRequest2->getErrorException()->getMessage());
    }

    /**
     * @covers \Saml2\LogoutRequest::isValid
     */
    public function testIsValid()
    {
        $request = file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request.xml');

        $encodedRequest = base64_encode(gzdeflate($request));

        $this->assertTrue((new LogoutRequest($this->settings, $encodedRequest))->isValid());

        $this->settings->setStrict(true);
        $this->assertFalse((new LogoutRequest($this->settings, $encodedRequest))->isValid());

        $this->settings->setStrict(false);

        $this->assertTrue(
            (new LogoutRequest(
                $this->settings,
                base64_encode(gzdeflate(str_replace('http://stuff.com/endpoints/endpoints/sls.php', Utils::getSelfURLNoQuery(), $request)))
            ))->isValid()
        );
    }

    /**
     * Tests that a 'true' value for compress => requests gets honored when we
     * try to obtain the request payload from getRequest()
     *
     * @covers \Saml2\LogoutRequest::getRequest()
     */
    public function testWeCanChooseToCompressARequest()
    {
        //Test that we can compress.
        $this->assertRegExp('#^<samlp:LogoutRequest#', gzinflate(base64_decode((new LogoutRequest(new Settings(require TEST_ROOT . '/settings/settings1.php')))->getRequest())));
    }

    /**
     * Tests that a 'false' value for compress => requests gets honored when we
     * try to obtain the request payload from getRequest()
     *
     * @covers \Saml2\LogoutRequest::getRequest()
     */
    public function testWeCanChooseNotToCompressARequest()
    {
        //Test that we can choose not to compress the request payload.
        $this->assertRegExp('#^<samlp:LogoutRequest#', base64_decode((new LogoutRequest(new Settings(require TEST_ROOT . '/settings/settings2.php')))->getRequest()));
    }

    /**
     * Tests that we can pass a boolean value to the getRequest()
     * method to choose whether it should 'gzdeflate' the body
     * of the request.
     *
     * @covers \Saml2\LogoutRequest::getRequest()
     */
    public function testWeCanChooseToDeflateARequestBody()
    {
        //Test that we can choose not to compress the request payload.
        //Compression is currently turned on in settings.
        $this->assertRegExp('#^<samlp:LogoutRequest#', base64_decode((new LogoutRequest(new Settings(require TEST_ROOT . '/settings/settings1.php')))->getRequest(false)));

        //Test that we can choose not to compress the request payload.
        //Compression is currently turned off in settings.
        $this->assertRegExp('#^<samlp:LogoutRequest#', gzinflate(base64_decode((new LogoutRequest(new Settings(require TEST_ROOT . '/settings/settings2.php')))->getRequest(true))));
    }

    /**
     * @covers \Saml2\LogoutRequest::isValid
     */
    public function testIsInValidSign()
    {
        $this->settings->setStrict(false);
        $_GET = [
            'SAMLRequest' => 'lVLBitswEP0Vo7tjeWzJtki8LIRCYLvbNksPewmyPc6K2pJqyXQ/v1LSQlroQi/DMJr33rwZbZ2cJysezNms/gt+X9H55G2etBOXlx1ZFy2MdMoJLWd0wvfieP/xQcCGCrsYb3ozkRvI+wjpHC5eGU2Sw35HTg3lA8hqZFwWFcMKsStpxbEsxoLXeQN9OdY1VAgk+YqLC8gdCUQB7tyKB+281D6UaF6mtEiBPudcABcMXkiyD26Ulv6CevXeOpFlVvlunb5ttEmV3ZjlnGn8YTRO5qx0NuBs8kzpAd829tXeucmR5NH4J/203I8el6gFRUqbFPJnyEV51Wq30by4TLW0/9ZyarYTxt4sBsjUYLMZvRykl1Fxm90SXVkfwx4P++T4KSafVzmpUcVJ/sfSrQZJPphllv79W8WKGtLx0ir8IrVTqD1pT2MH3QAMSs4KTvui71jeFFiwirOmprwPkYW063+5uRq4urHiiC4e8hCX3J5wqAEGaPpw9XB5JmkBdeDqSlkz6CmUXdl0Qae5kv2F/1384wu3PwE=',
            'RelayState' => '_1037fbc88ec82ce8e770b2bed1119747bb812a07e6',
            'SigAlg' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
            'Signature' => 'XCwCyI5cs7WhiJlB5ktSlWxSBxv+6q2xT3c8L7dLV6NQG9LHWhN7gf8qNsahSXfCzA0Ey9dp5BQ0EdRvAk2DIzKmJY6e3hvAIEp1zglHNjzkgcQmZCcrkK9Czi2Y1WkjOwR/WgUTUWsGJAVqVvlRZuS3zk3nxMrLH6f7toyvuJc=',
        ];

        $encodedRequest = $_GET['SAMLRequest'];

        $this->assertTrue((new LogoutRequest($this->settings, $encodedRequest))->isValid());

        $this->settings->setStrict(true);
        $logoutRequest2 = new LogoutRequest($this->settings, $encodedRequest);

        $this->assertFalse($logoutRequest2->isValid());
        $this->assertStringContainsString('The LogoutRequest was received at', $logoutRequest2->getErrorException()->getMessage());

        $this->settings->setStrict(false);
        $oldSignature = $_GET['Signature'];
        $_GET['Signature'] = 'vfWbbc47PkP3ejx4bjKsRX7lo9Ml1WRoE5J5owF/0mnyKHfSY6XbhO1wwjBV5vWdrUVX+xp6slHyAf4YoAsXFS0qhan6txDiZY4Oec6yE+l10iZbzvie06I4GPak4QrQ4gAyXOSzwCrRmJu4gnpeUxZ6IqKtdrKfAYRAcVf3333=';

        $logoutRequest3 = new LogoutRequest($this->settings, $encodedRequest);

        $this->assertFalse($logoutRequest3->isValid());
        $this->assertStringContainsString('Signature validation failed. Logout Request rejected', $logoutRequest3->getErrorException()->getMessage());

        $_GET['Signature'] = $oldSignature;
        $oldSigAlg = $_GET['SigAlg'];
        unset($_GET['SigAlg']);

        $this->assertTrue($logoutRequest3->isValid());

        $_GET['RelayState'] = 'http://example.com/relaystate';

        $this->assertFalse($logoutRequest3->isValid());
        $this->assertStringContainsString('Signature validation failed. Logout Request rejected', $logoutRequest3->getErrorException()->getMessage());

        $this->settings->setStrict(true);

        $encodedRequest2 = base64_encode(
            gzdeflate(
                str_replace(
                    'https://pitbulk.no-ip.org/simplesaml/saml2/idp/metadata.php',
                    'http://idp.example.com/',
                    str_replace(
                        'https://pitbulk.no-ip.org/newonelogin/demo1/index.php?sls',
                        Utils::getSelfURLNoQuery(),
                        gzinflate(base64_decode($_GET['SAMLRequest']))
                    )
                )
            )
        );

        $_GET['SAMLRequest'] = $encodedRequest2;
        $logoutRequest4 = new LogoutRequest($this->settings, $encodedRequest2);

        $this->assertFalse($logoutRequest4->isValid());
        $this->assertSame('Signature validation failed. Logout Request rejected', $logoutRequest4->getErrorException()->getMessage());

        $this->settings->setStrict(false);
        $logoutRequest5 = new LogoutRequest($this->settings, $encodedRequest2);

        $this->assertFalse($logoutRequest5->isValid());
        $this->assertSame('Signature validation failed. Logout Request rejected', $logoutRequest5->getErrorException()->getMessage());

        $_GET['SigAlg'] = 'http://www.w3.org/2000/09/xmldsig#dsa-sha1';

        $this->assertFalse($logoutRequest5->isValid());
        $this->assertSame('Invalid signAlg in the received Logout Request', $logoutRequest5->getErrorException()->getMessage());

        $settingsInfo = require TEST_ROOT . '/settings/settings1.php';
        $settingsInfo['strict'] = true;
        $settingsInfo['security']['wantMessagesSigned'] = true;

        $_GET['SigAlg'] = $oldSigAlg;
        $oldSignature = $_GET['Signature'];
        unset($_GET['Signature']);
        $logoutRequest6 = new LogoutRequest(new Settings($settingsInfo), $encodedRequest2);

        $this->assertFalse($logoutRequest6->isValid());
        $this->assertSame('The Message of the Logout Request is not signed and the SP require it', $logoutRequest6->getErrorException()->getMessage());

        $_GET['Signature'] = $oldSignature;

        $settingsInfo['idp']['certFingerprint'] = 'afe71c28ef740bc87425be13a2263d37971da1f9';
        unset($settingsInfo['idp']['x509cert']);
        $logoutRequest7 = new LogoutRequest(new Settings($settingsInfo), $encodedRequest2);

        $this->assertFalse($logoutRequest7->isValid());
        $this->assertStringContainsString('In order to validate the sign on the Logout Request, the x509cert of the IdP is required', $logoutRequest7->getErrorException()->getMessage());
    }

    /**
     * Case: Using x509certMulti
     *
     * @covers \Saml2\LogoutRequest::isValid
     */
    public function testIsValidSignUsingX509certMulti()
    {
        $_GET = [
            'SAMLRequest' => 'fZJNa+MwEIb/itHdiTz6sC0SQyEsBPoB27KHXoIsj7cGW3IlGfLzV7G7kN1DL2KYmeedmRcdgp7GWT26326JP/FzwRCz6zTaoNbKkSzeKqfDEJTVEwYVjXp9eHpUsKNq9i4640Zyh3xP6BDQx8FZkp1PR3KpqexAl72QmpUCS8SW01IiZz2TVVGD4X1VQYlAsl/oQyKPJAklPIQFzzZEbWNK0YLnlOVA3wqpQCoB7yQ7pWsGq+NKfcQ4q/0+xKXvd8ZNe7Td7AYbw10UxrCbP2aSPbv4Yl/8Qx/R3+SB5bTOoXiDQvFNvjnc7lXrIr75kh+6eYdXPc0jrkMO+/umjXhOtpxP2Q/nJx2/9+uWGbq8X1tV9NqGAW0kzaVvoe1AAJeCSWqYaUVRM2SilKKuqDTpFSlszdcK29RthVm9YriZebYdXpsLdhVAB7VJzif3haYMqqTVcl0JMBR4y+s2zak3sf/4v8l/vlHzBw==',
            'RelayState' => '_1037fbc88ec82ce8e770b2bed1119747bb812a07e6',
            'SigAlg' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
            'Signature' => 'Ouxo9BV6zmq4yrgamT9EbSKy/UmvSxGS8z26lIMgKOEP4LFR/N23RftdANmo4HafrzSfA0YTXwhKDqbOByS0j+Ql8OdQOes7vGioSjo5qq/Bi+5i6jXwQfphnfcHAQiJL4gYVIifkhhHRWpvYeiysF1Y9J02me0izwazFmoRXr4=',
        ];

        $settingsInfo = require TEST_ROOT . '/settings/settings6.php';
        $settingsInfo['strict'] = true;
        $settingsInfo['security']['wantMessagesSigned'] = true;
        $settingsInfo['baseurl'] = "http://stuff.com/endpoints/endpoints/";
        $settings = new Settings($settingsInfo);
        $_SERVER['REQUEST_URI'] = "/endpoints/endpoints/sls.php";
        unset($_SERVER['REQUEST_URI']);
        Utils::setBaseURL(null);
        $this->assertTrue((new LogoutRequest($settings, $_GET['SAMLRequest']))->isValid());
    }

    /**
     * Tests that we can get the request XML directly without
     * going through intermediate steps
     *
     * @covers \Saml2\LogoutRequest::getXML()
     */
    public function testGetXML()
    {
        $settings = new Settings(require TEST_ROOT . '/settings/settings1.php');
        $xml = (new LogoutRequest($settings))->getXML();
        $this->assertRegExp('#^<samlp:LogoutRequest#', $xml);

        $this->assertRegExp('#^<samlp:LogoutRequest#', (new LogoutRequest($settings, base64_encode($xml)))->getXML());
    }

    /**
     * Tests that we can get the ID of the LogoutRequest
     *
     * @covers \Saml2\LogoutRequest::getID()
     */
    public function testGetID()
    {
        $settings = new Settings(require TEST_ROOT . '/settings/settings1.php');
        $xml = (new LogoutRequest($settings))->getXML();
        $id1 = LogoutRequest::getID($xml);
        $this->assertNotNull($id1);

        $this->assertSame($id1, (new LogoutRequest($settings, base64_encode($xml)))->id);
    }

    /**
     * Tests that the LogoutRequest throws an exception
     *
     * @covers \Saml2\LogoutRequest::getID()
     */
    public function testGetIDException()
    {
        $this->expectException(Error::class);
        $this->expectExceptionMessage("LogoutRequest could not be processed");
        LogoutRequest::getID((new LogoutRequest(new Settings(require TEST_ROOT . '/settings/settings1.php')))->getXML() . '<garbage>');
    }
}
