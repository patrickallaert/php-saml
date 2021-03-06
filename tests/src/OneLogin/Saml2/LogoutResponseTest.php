<?php

namespace Saml2\Tests;

use Saml2\Constants;
use Saml2\Error;
use Saml2\LogoutResponse;
use Saml2\Settings;
use Saml2\Utils;

class LogoutResponseTest extends \PHPUnit\Framework\TestCase
{
    private $settings;


    public function setUp(): void
    {
        $this->settings = new Settings(require TEST_ROOT . '/settings/settings1.php');
    }

    /**
     * @covers \Saml2\LogoutResponse
     */
    public function testConstructor()
    {
        $this->assertRegExp(
            '#<samlp:LogoutResponse#',
            (new LogoutResponse(
                $this->settings,
                file_get_contents(TEST_ROOT . '/data/logout_responses/logout_response_deflated.xml.base64')
            ))->document->saveXML()
        );
    }

    /**
     * The creation of a deflated SAML Logout Response
     *
     * @covers \Saml2\LogoutResponse
     */
    public function testCreateDeflatedSAMLLogoutResponseURLParameter()
    {
        $responseBuilder = new LogoutResponse($this->settings);
        $responseBuilder->build('ONELOGIN_21584ccdfaca36a145ae990442dcd96bfe60151e');
        $logoutUrl = Utils::redirect('http://idp.example.com/SingleLogoutService.php', ['SAMLResponse' => $responseBuilder->getResponse()], true);

        $this->assertRegExp('#^http://idp\.example\.com\/SingleLogoutService\.php\?SAMLResponse=#', $logoutUrl);
        parse_str(parse_url($logoutUrl, PHP_URL_QUERY), $exploded);
        // parse_url already urldecode de params so is not required.
        $this->assertRegExp('#^<samlp:LogoutResponse#', gzinflate(base64_decode($exploded['SAMLResponse'])));
    }

    /**
     * @covers \Saml2\LogoutResponse::getStatus
     */
    public function testGetStatus()
    {
        $this->assertSame(
            Constants::STATUS_SUCCESS,
            (new LogoutResponse($this->settings, file_get_contents(TEST_ROOT . '/data/logout_responses/logout_response_deflated.xml.base64')))->getStatus()
        );

        $this->assertNull(
            (new LogoutResponse($this->settings, file_get_contents(TEST_ROOT . '/data/logout_responses/invalids/no_status.xml.base64')))->getStatus()
        );
    }

    /**
     * @covers \Saml2\LogoutResponse::getIssuer
     */
    public function testGetIssuer()
    {
        $response = new LogoutResponse($this->settings, file_get_contents(TEST_ROOT . '/data/logout_responses/logout_response_deflated.xml.base64'));

        $this->assertSame('http://idp.example.com/', $response->getIssuer());
    }

    /**
     * @covers \Saml2\LogoutResponse::getErrorException
     */
    public function testGetErrorException()
    {
        $response = new LogoutResponse($this->settings, file_get_contents(TEST_ROOT . '/data/logout_responses/logout_response_deflated.xml.base64'));
        $this->settings->setStrict(true);
        $this->assertFalse($response->isValid('invalid_request_id'));
        $this->assertSame(
            'The InResponseTo of the Logout Response: ONELOGIN_21584ccdfaca36a145ae990442dcd96bfe60151e, does not match the ID of the Logout request sent by the SP: invalid_request_id',
            $response->getErrorException()->getMessage()
        );
    }

    /**
     * Case invalid request Id
     *
     * @covers \Saml2\LogoutResponse::isValid
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testIsInValidRequestId()
    {
        $message = base64_encode(
            gzdeflate(
                str_replace(
                    'http://stuff.com/endpoints/endpoints/sls.php',
                    Utils::getSelfURLNoQuery(),
                    gzinflate(base64_decode(file_get_contents(TEST_ROOT . '/data/logout_responses/logout_response_deflated.xml.base64')))
                )
            )
        );

        $requestId = 'invalid_request_id';

        $this->settings->setStrict(false);
        $this->assertTrue((new LogoutResponse($this->settings, $message))->isValid($requestId));

        $this->settings->setStrict(true);
        $response2 = new LogoutResponse($this->settings, $message);

        $this->assertTrue($response2->isValid());

        $this->assertFalse($response2->isValid($requestId));
        $this->assertStringContainsString('The InResponseTo of the Logout Response:', $response2->getErrorException()->getMessage());
    }

    /**
     * Case invalid Issuer
     *
     * @covers \Saml2\LogoutResponse::isValid
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testIsInValidIssuer()
    {
        $message = base64_encode(
            gzdeflate(
                str_replace(
                    'http://idp.example.com/',
                    'http://invalid.issuer.example.com',
                    str_replace(
                        'http://stuff.com/endpoints/endpoints/sls.php',
                        Utils::getSelfURLNoQuery(),
                        gzinflate(base64_decode(file_get_contents(TEST_ROOT . '/data/logout_responses/logout_response_deflated.xml.base64')))
                    )
                )
            )
        );

        $this->settings->setStrict(false);
        $this->assertTrue((new LogoutResponse($this->settings, $message))->isValid());

        $this->settings->setStrict(true);
        $response2 = new LogoutResponse($this->settings, $message);

        $this->assertFalse($response2->isValid());
        $this->assertSame('Invalid issuer in the Logout Response', $response2->getErrorException()->getMessage());
    }

    /**
     * Case invalid xml
     *
     * @covers \Saml2\LogoutResponse::isValid
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testIsInValidWrongXML()
    {
        $settingsInfo = require TEST_ROOT . '/settings/settings1.php';

        $settingsInfo['security']['wantXMLValidation'] = false;

        $settings = new Settings($settingsInfo);
        $settings->setStrict(false);

        $message = file_get_contents(TEST_ROOT . '/data/logout_responses/invalids/invalid_xml.xml.base64');

        $this->assertTrue((new LogoutResponse($settings, $message))->isValid());

        $settings->setStrict(true);
        $response2 = new LogoutResponse($settings, $message);
        $response2->isValid();
        $this->assertNotEquals('Invalid SAML Logout Response. Not match the saml-schema-protocol-2.0.xsd', $response2->getErrorException()->getMessage());

        $settingsInfo['security']['wantXMLValidation'] = true;
        $settings2 = new Settings($settingsInfo);
        $settings2->setStrict(false);
        $this->assertTrue((new LogoutResponse($settings2, $message))->isValid());

        $settings2->setStrict(true);
        $response4 = new LogoutResponse($settings2, $message);
        $this->assertFalse($response4->isValid());
        $this->assertSame('Invalid SAML Logout Response. Not match the saml-schema-protocol-2.0.xsd', $response4->getErrorException()->getMessage());
    }

    /**
     * Case invalid Destination
     *
     * @covers \Saml2\LogoutResponse::isValid
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testIsInValidDestination()
    {
        $message = file_get_contents(TEST_ROOT . '/data/logout_responses/logout_response_deflated.xml.base64');

        $this->settings->setStrict(false);
        $this->assertTrue((new LogoutResponse($this->settings, $message))->isValid());

        $this->settings->setStrict(true);
        $response2 = new LogoutResponse($this->settings, $message);
        $this->assertFalse($response2->isValid());
        $this->assertStringContainsString('The LogoutResponse was received at', $response2->getErrorException()->getMessage());
    }

    /**
     *
     * @covers \Saml2\LogoutResponse::isValid
     */
    public function testIsInValidSign()
    {
        $this->settings->setStrict(false);
        $_GET = [
            'SAMLResponse' => 'fZJva8IwEMa/Ssl7TZrW/gnqGHMMwSlM8cXeyLU9NaxNQi9lfvxVZczB5ptwSe733MPdjQma2qmFPdjOvyE5awiDU1MbUpevCetaoyyQJmWgQVK+VOvH14WSQ6Fca70tbc1ukPsEEGHrtTUsmM8mbDfKUhnFci8gliGINI/yXIAAiYnsw6JIRgWWAKlkwRZb6skJ64V6nKjDuSEPxvdPIowHIhpIsQkTFaYqSt9ZMEPy2oC/UEfvHSnOnfZFV38MjR1oN7TtgRv8tAZre9CGV9jYkGtT4Wnoju6Bauprme/ebOyErZbPi9XLfLnDoohwhHGc5WVSVhjCKM6rBMpYQpWJrIizfZ4IZNPxuTPqYrmd/m+EdONqPOfy8yG5rhxv0EMFHs52xvxWaHyd3tqD7+j37clWGGyh7vD+POiSrdZdWSIR49NrhR9R/teGTL8A',
            'RelayState' => 'https://pitbulk.no-ip.org/newonelogin/demo1/index.php',
            'SigAlg' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
            'Signature' => 'vfWbbc47PkP3ejx4bjKsRX7lo9Ml1WRoE5J5owF/0mnyKHfSY6XbhO1wwjBV5vWdrUVX+xp6slHyAf4YoAsXFS0qhan6txDiZY4Oec6yE+l10iZbzvie06I4GPak4QrQ4gAyXOSzwCrRmJu4gnpeUxZ6IqKtdrKfAYRAcVfNKGA=',
        ];

        $this->assertTrue((new LogoutResponse($this->settings, $_GET['SAMLResponse']))->isValid());

        $this->settings->setStrict(true);
        $response2 = new LogoutResponse($this->settings, $_GET['SAMLResponse']);
        $this->assertFalse($response2->isValid());
        $this->assertStringContainsString('Invalid issuer in the Logout Response', $response2->getErrorException()->getMessage());

        $this->settings->setStrict(false);
        $oldSignature = $_GET['Signature'];
        $_GET['Signature'] = 'vfWbbc47PkP3ejx4bjKsRX7lo9Ml1WRoE5J5owF/0mnyKHfSY6XbhO1wwjBV5vWdrUVX+xp6slHyAf4YoAsXFS0qhan6txDiZY4Oec6yE+l10iZbzvie06I4GPak4QrQ4gAyXOSzwCrRmJu4gnpeUxZ6IqKtdrKfAYRAcVf3333=';
        $response3 = new LogoutResponse($this->settings, $_GET['SAMLResponse']);

        $this->assertFalse($response3->isValid());
        $this->assertSame('Signature validation failed. Logout Response rejected', $response3->getErrorException()->getMessage());

        $_GET['Signature'] = $oldSignature;
        $oldSigAlg = $_GET['SigAlg'];
        unset($_GET['SigAlg']);
        $this->assertTrue((new LogoutResponse($this->settings, $_GET['SAMLResponse']))->isValid());

        $_GET['RelayState'] = 'http://example.com/relaystate';
        $response5 = new LogoutResponse($this->settings, $_GET['SAMLResponse']);
        $this->assertFalse($response5->isValid());
        $this->assertSame('Signature validation failed. Logout Response rejected', $response5->getErrorException()->getMessage());

        $this->settings->setStrict(true);

        $_GET['SAMLResponse'] = base64_encode(
            gzdeflate(
                str_replace(
                    'https://pitbulk.no-ip.org/simplesaml/saml2/idp/metadata.php',
                    'http://idp.example.com/',
                    str_replace(
                        'https://pitbulk.no-ip.org/newonelogin/demo1/index.php?sls',
                        Utils::getSelfURLNoQuery(),
                        gzinflate(base64_decode($_GET['SAMLResponse']))
                    )
                )
            )
        );

        $response6 = new LogoutResponse($this->settings, $_GET['SAMLResponse']);
        $this->assertFalse($response6->isValid());
        $this->assertSame('Signature validation failed. Logout Response rejected', $response6->getErrorException()->getMessage());

        $this->settings->setStrict(false);
        $response7 = new LogoutResponse($this->settings, $_GET['SAMLResponse']);
        $this->assertFalse($response7->isValid());
        $this->assertSame('Signature validation failed. Logout Response rejected', $response7->getErrorException()->getMessage());

        $_GET['SigAlg'] = 'http://www.w3.org/2000/09/xmldsig#dsa-sha1';
        $response8 = new LogoutResponse($this->settings, $_GET['SAMLResponse']);
        $this->assertFalse($response8->isValid());
        $this->assertSame('Invalid signAlg in the received Logout Response', $response8->getErrorException()->getMessage());

        $settingsInfo = require TEST_ROOT . '/settings/settings1.php';
        $settingsInfo['strict'] = true;
        $settingsInfo['security']['wantMessagesSigned'] = true;

        $_GET['SigAlg'] = $oldSigAlg;
        $oldSignature = $_GET['Signature'];
        unset($_GET['Signature']);
        $_GET['SAMLResponse'] = base64_encode(
            gzdeflate(
                str_replace(
                    'https://pitbulk.no-ip.org/simplesaml/saml2/idp/metadata.php',
                    'http://idp.example.com/',
                    str_replace(
                        'https://pitbulk.no-ip.org/newonelogin/demo1/index.php?sls',
                        Utils::getSelfURLNoQuery(),
                        gzinflate(base64_decode($_GET['SAMLResponse']))
                    )
                )
            )
        );
        $response9 = new LogoutResponse(new Settings($settingsInfo), $_GET['SAMLResponse']);
        $this->assertFalse($response9->isValid());
        $this->assertSame('The Message of the Logout Response is not signed and the SP requires it', $response9->getErrorException()->getMessage());

        $_GET['Signature'] = $oldSignature;

        $settingsInfo['idp']['certFingerprint'] = 'afe71c28ef740bc87425be13a2263d37971da1f9';
        unset($settingsInfo['idp']['x509cert']);
        $response10 = new LogoutResponse(new Settings($settingsInfo), $_GET['SAMLResponse']);
        $this->assertFalse($response10->isValid());
        $this->assertSame('In order to validate the sign on the Logout Response, the x509cert of the IdP is required', $response10->getErrorException()->getMessage());
    }

    /**
     * Case: Using x509certMulti
     *
     * @covers \Saml2\LogoutResponse::isValid
     */
    public function testIsValidSignUsingX509certMulti()
    {
        $_GET = [
            'SAMLResponse' => 'fZHbasJAEIZfJey9ZrNZc1gSodRSBKtQxYveyGQz1kCyu2Q24OM3jS21UHo3p++f4Z+CoGud2th3O/hXJGcNYXDtWkNqapVs6I2yQA0pAx2S8lrtH142Ssy5cr31VtuW3SH/E0CEvW+sYcF6VbLTIktFLMWZgxQR8DSP85wDB4GJGMOqShYVaoBUsOCIPY1kyUahEScacG3Ig/FjiUdyxuOZ4IcoUVGq4vSNBSsk3xjwE3Xx3qkwJD+cz3NtuxBN7WxjPN1F1NLcXdwob77tONiS7bZPm93zenvCqopxgVJmuU50jREsZF4noKWAOuNZJbNznnBky+LTDDVd2S+/dje1m+MVOtfidEER3g8Vt2fsPfiBfmePtsbgCO2A/9tL07TaD1ojEQuXtw0/ouFfD19+AA==',
            'RelayState' => 'http://stuff.com/endpoints/endpoints/index.php',
            'SigAlg' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
            'Signature' => 'OV9c4R0COSjN69fAKCpV7Uj/yx6/KFxvbluVCzdK3UuortpNMpgHFF2wYNlMSG9GcYGk6p3I8nB7Z+1TQchMWZOlO/StjAqgtZhtpiwPcWryNuq8vm/6hnJ3zMDhHTS7F8KG4qkCXmJ9sQD3Y31UNcuygBwIbNakvhDT5Qo9Nsw=',
        ];

        $settingsInfo = require TEST_ROOT . '/settings/settings6.php';
        $settingsInfo['strict'] = true;
        $settingsInfo['security']['wantMessagesSigned'] = true;
        $settingsInfo['baseurl'] = "http://stuff.com/endpoints/endpoints/";
        $settings = new Settings($settingsInfo);
        $_SERVER['REQUEST_URI'] = "/endpoints/endpoints/sls.php";
        $valid = (new LogoutResponse($settings, $_GET['SAMLResponse']))->isValid();
        unset($_SERVER['REQUEST_URI']);
        Utils::setBaseURL(null);
        $this->assertTrue($valid);
    }

    /**
     * @covers \Saml2\LogoutResponse::isValid
     */
    public function testIsValid()
    {
        $message = file_get_contents(TEST_ROOT . '/data/logout_responses/logout_response_deflated.xml.base64');
        $this->assertTrue((new LogoutResponse($this->settings, $message))->isValid());

        $this->settings->setStrict(true);
        $response2 = new LogoutResponse($this->settings, $message);
        $this->assertFalse($response2->isValid());
        $this->assertStringContainsString('The LogoutResponse was received at', $response2->getErrorException()->getMessage());

        $this->assertTrue(
            (new LogoutResponse(
                $this->settings,
                base64_encode(
                    gzdeflate(
                        str_replace('http://stuff.com/endpoints/endpoints/sls.php', Utils::getSelfURLNoQuery(), gzinflate(base64_decode($message)))
                    )
                )
            ))->isValid()
        );
    }

    /**
     * Tests that a 'true' value for compress => responses gets honored when we
     * try to obtain the request payload from getResponse()
     *
     * @covers \Saml2\LogoutResponse::getResponse()
     */
    public function testWeCanChooseToCompressAResponse()
    {
        //Test that we can compress.
        $this->assertRegExp(
            '#^<samlp:LogoutResponse#',
            gzinflate(
                base64_decode(
                    (new LogoutResponse(
                        new Settings(require TEST_ROOT . '/settings/settings1.php'),
                        file_get_contents(
                            TEST_ROOT . '/data/logout_responses/logout_response_deflated.xml.base64'
                        )
                    ))->getResponse()
                )
            )
        );
    }

    /**
     * Tests that a 'false' value for compress => responses gets honored when we
     * try to obtain the request payload from getResponse()
     *
     * @covers \Saml2\LogoutResponse::getResponse()
     */
    public function testWeCanChooseNotToCompressAResponse()
    {
        //Test that we can choose not to compress the request payload.
        $this->assertRegExp(
            '#^<samlp:LogoutResponse#',
            base64_decode(
                (new LogoutResponse(
                    new Settings(require TEST_ROOT . '/settings/settings2.php'),
                    file_get_contents(
                        TEST_ROOT . '/data/logout_responses/logout_response_deflated.xml.base64'
                    )
                ))->getResponse()
            )
        );
    }

    /**
     * Test that we can choose to compress or not compress the request payload
     * with getResponse() method.
     *
     * @covers \Saml2\LogoutResponse::getResponse()
     */
    public function testWeCanChooseToDeflateAResponseBody()
    {
        $message = file_get_contents(
            TEST_ROOT . '/data/logout_responses/logout_response_deflated.xml.base64'
        );

        $this->assertRegExp('#^<samlp:LogoutResponse#', base64_decode((new LogoutResponse(new Settings(require TEST_ROOT . '/settings/settings1.php'), $message))->getResponse(false)));

        $this->assertRegExp(
            '#^<samlp:LogoutResponse#',
            gzinflate(base64_decode((new LogoutResponse(new Settings(require TEST_ROOT . '/settings/settings2.php'), $message))->getResponse(true)))
        );
    }

    /**
     * Tests that we can get the ID of the LogoutResponse
     *
     * @covers \Saml2\LogoutRequest::getID()
     */
    public function testGetID()
    {
        $logoutResponse = new LogoutResponse(new Settings(require TEST_ROOT . '/settings/settings1.php'));
        $logoutResponse->build('jhgvsadja');

        $this->assertStringStartsWith("ONELOGIN_", $logoutResponse->id);
    }

    /**
     * Tests that the LogoutRequest throws an exception
     *
     * @covers \Saml2\LogoutRequest::getID()
     */
    public function testGetIDException()
    {
        $this->expectException(Error::class);
        $this->expectExceptionMessage("LogoutResponse could not be processed");
        new LogoutResponse(new Settings(require TEST_ROOT . '/settings/settings1.php'), '<garbage>');
    }
}
