<?php

namespace Saml2\Tests;

use Exception;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use Saml2\Auth;
use Saml2\Constants;
use Saml2\Error;
use Saml2\LogoutRequest;
use Saml2\Settings;
use Saml2\Utils;
use Saml2\ValidationError;

class AuthTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @var Auth
     */
    private $auth;

    /**
     * @var array
     */
    private $settingsInfo;


    public function setUp(): void
    {
        $this->settingsInfo = require TEST_ROOT . '/settings/settings1.php';
        $this->auth = new Auth($this->settingsInfo);
    }

    /**
     * Build a Settings object with a setting array
     * and compare the value returned from the method of the
     * $auth object
     *
     * @covers \Saml2\Auth::getSettings
     */
    public function testGetSettings()
    {
        $this->assertEquals($this->auth->getSettings(), new Settings(require TEST_ROOT . '/settings/settings1.php'));
    }

    /**
     * @covers \Saml2\Auth::getLastRequestID
     */
    public function testGetLastRequestID()
    {
        $this->auth->login(null, [], false, false, true, false);
        $id1 = $this->auth->getLastRequestID();
        $this->assertNotNull($id1);

        $this->auth->logout(null, [], null, null, true, null);
        $id2 = $this->auth->getLastRequestID();
        $this->assertNotNull($id2);

        $this->assertNotEquals($id1, $id2);
    }

    /**
     * Case No Response, An exception is throw
     *
     * @covers \Saml2\Auth::processResponse
     */
    public function testProcessNoResponse()
    {
        try {
            $this->auth->processResponse();
            $this->fail('Error was not raised');
        } catch (Error $e) {
            $this->assertStringContainsString('SAML Response not found', $e->getMessage());
        }

        $this->assertSame(['invalid_binding'], $this->auth->getErrors());
    }

    /**
     * Case Invalid Response, After processing the response the user
     * is not authenticated, attributes are notreturned, no nameID and
     * the error array is not empty, contains 'invalid_response
     *
     * @covers \Saml2\Auth::processResponse
     * @covers \Saml2\Auth::isAuthenticated
     * @covers \Saml2\Auth::getAttributes
     * @covers \Saml2\Auth::getAttribute
     * @covers \Saml2\Auth::getNameId
     * @covers \Saml2\Auth::getNameIdFormat
     * @covers \Saml2\Auth::getNameIdNameQualifier
     * @covers \Saml2\Auth::getNameIdSPNameQualifier
     * @covers \Saml2\Auth::getErrors
     * @covers \Saml2\Auth::getSessionIndex
     * @covers \Saml2\Auth::getSessionExpiration
     * @covers \Saml2\Auth::getLastErrorException
     */
    public function testProcessResponseInvalid()
    {
        $_POST['SAMLResponse'] = file_get_contents(TEST_ROOT . '/data/responses/response1.xml.base64');

        $this->auth->processResponse();

        $this->assertFalse($this->auth->isAuthenticated());
        $this->assertEmpty($this->auth->getAttributes());
        $this->assertNull($this->auth->getNameId());
        $this->assertNull($this->auth->getNameIdFormat());
        $this->assertNull($this->auth->getNameIdNameQualifier());
        $this->assertNull($this->auth->getNameIdSPNameQualifier());
        $this->assertNull($this->auth->getSessionIndex());
        $this->assertNull($this->auth->getSessionExpiration());
        $this->assertNull($this->auth->getAttribute('uid'));
        $this->assertSame(['invalid_response'], $this->auth->getErrors());
        $this->assertSame("Reference validation failed", $this->auth->getLastErrorException()->getMessage());
    }

    /**
     * Case Invalid Response, Invalid requestID
     *
     * @covers \Saml2\Auth::processResponse
     */
    public function testProcessResponseInvalidRequestId()
    {
        $_POST['SAMLResponse'] = base64_encode(
            str_replace(
                'http://stuff.com/endpoints/endpoints/acs.php',
                Utils::getSelfURLNoQuery(),
                base64_decode(file_get_contents(TEST_ROOT . '/data/responses/unsigned_response.xml.base64'))
            )
        );

        $requestId = 'invalid';
        $this->auth->processResponse($requestId);

        $this->assertSame("No Signature found. SAML Response rejected", $this->auth->getLastErrorException()->getMessage());

        $this->auth->setStrict(true);
        $this->auth->processResponse($requestId);
        $this->assertSame("The InResponseTo of the Response: _57bcbf70-7b1f-012e-c821-782bcb13bb38, does not match the ID of the AuthNRequest sent by the SP: invalid", $this->auth->getLastErrorException()->getMessage());

        $this->auth->processResponse('_57bcbf70-7b1f-012e-c821-782bcb13bb38');
        $this->assertSame("No Signature found. SAML Response rejected", $this->auth->getLastErrorException()->getMessage());
    }

    /**
     * Case Valid Response, After processing the response the user
     * is authenticated, attributes are returned, also has a nameID and
     * the error array is empty
     *
     * @covers \Saml2\Auth::processResponse
     * @covers \Saml2\Auth::isAuthenticated
     * @covers \Saml2\Auth::getAttributes
     * @covers \Saml2\Auth::getAttribute
     * @covers \Saml2\Auth::getNameId
     * @covers \Saml2\Auth::getNameIdFormat
     * @covers \Saml2\Auth::getSessionIndex
     * @covers \Saml2\Auth::getSessionExpiration
     * @covers \Saml2\Auth::getErrors
     */
    public function testProcessResponseValid()
    {
        $_POST['SAMLResponse'] = file_get_contents(TEST_ROOT . '/data/responses/valid_response.xml.base64');

        $this->auth->processResponse();
        $this->assertTrue($this->auth->isAuthenticated());
        $this->assertSame('492882615acf31c8096b627245d76ae53036c090', $this->auth->getNameId());
        $this->assertSame(Constants::NAMEID_EMAIL_ADDRESS, $this->auth->getNameIdFormat());
        $attributes = $this->auth->getAttributes();
        $this->assertNotEmpty($attributes);
        $this->assertSame($attributes['mail'], $this->auth->getAttribute('mail'));
        $this->assertSame('_6273d77b8cde0c333ec79d22a9fa0003b9fe2d75cb', $this->auth->getSessionIndex());
        $this->assertSame(2655106621, $this->auth->getSessionExpiration());
    }

    /**
     * Case found
     * @covers \Saml2\Auth::getNameIdNameQualifier
     */
    public function testGetNameIdNameQualifier()
    {
        $_POST['SAMLResponse'] = file_get_contents(TEST_ROOT . '/data/responses/valid_response_with_namequalifier.xml.base64');
        $this->assertNull($this->auth->getNameIdNameQualifier());
        $this->auth->processResponse();
        $this->assertTrue($this->auth->isAuthenticated());
        $this->assertSame('https://test.example.com/saml/metadata', $this->auth->getNameIdNameQualifier());
    }

    /**
     * Case Null
     * @covers \Saml2\Auth::getNameIdNameQualifier
     */
    public function testGetNameIdNameQualifier2()
    {
        $_POST['SAMLResponse'] = file_get_contents(TEST_ROOT . '/data/responses/valid_response.xml.base64');
        $this->assertNull($this->auth->getNameIdNameQualifier());
        $this->auth->processResponse();
        $this->assertTrue($this->auth->isAuthenticated());
        $this->assertNull($this->auth->getNameIdNameQualifier());
    }

    /**
     * Case Found
     * @covers \Saml2\Auth::getNameIdSPNameQualifier
     */
    public function testGetNameIdSPNameQualifier()
    {
        $_POST['SAMLResponse'] = file_get_contents(TEST_ROOT . '/data/responses/valid_response_with_namequalifier.xml.base64');
        $this->assertNull($this->auth->getNameIdSPNameQualifier());
        $this->auth->processResponse();
        $this->assertTrue($this->auth->isAuthenticated());
        $this->assertNull($this->auth->getNameIdSPNameQualifier());
    }

    /**
     * Case Null
     * @covers \Saml2\Auth::getNameIdSPNameQualifier
     */
    public function testGetNameIdSPNameQualifier2()
    {
        $_POST['SAMLResponse'] = file_get_contents(TEST_ROOT . '/data/responses/valid_response.xml.base64');
        $this->assertNull($this->auth->getNameIdSPNameQualifier());
        $this->auth->processResponse();
        $this->assertTrue($this->auth->isAuthenticated());
        $this->assertSame('http://stuff.com/endpoints/metadata.php', $this->auth->getNameIdSPNameQualifier());
    }

    /**
     * @covers \Saml2\Auth::getAttributes
     * @covers \Saml2\Auth::getAttribute
     * @covers \Saml2\Auth::getAttributesWithFriendlyName
     * @covers \Saml2\Auth::getAttributeWithFriendlyName
     */
    public function testGetAttributes()
    {
        $auth = new Auth($this->settingsInfo);
        $_POST['SAMLResponse'] = file_get_contents(TEST_ROOT . '/data/responses/response6.xml.base64');
        $auth->processResponse();
        $this->assertSame(
            [
                'urn:oid:0.9.2342.19200300.100.1.1' => ['demo'],
                'urn:oid:2.5.4.42' => ['value'],
            ],
            $auth->getAttributes()
        );
        $this->assertSame(
            [
                'uid' => ['demo'],
                'givenName' => ['value'],
            ],
            $auth->getAttributesWithFriendlyName()
        );
        $this->assertNull($auth->getAttribute('givenName'));
        $this->assertSame(['value'], $auth->getAttributeWithFriendlyName('givenName'));
        $this->assertSame(['value'], $auth->getAttribute('urn:oid:2.5.4.42'));
        $this->assertNull($auth->getAttributeWithFriendlyName('urn:oid:2.5.4.42'));
        // An assertion that has no attributes should return an empty array when asked for the attributes
        $_POST['SAMLResponse'] = file_get_contents(TEST_ROOT . '/data/responses/response2.xml.base64');
        $auth2 = new Auth($this->settingsInfo);
        $auth2->processResponse();
        $this->assertEmpty($auth2->getAttributes());
        $this->assertEmpty($auth2->getAttributesWithFriendlyName());
        // Encrypted Attributes are not supported
        $_POST['SAMLResponse'] = file_get_contents(TEST_ROOT . '/data/responses/invalids/encrypted_attrs.xml.base64');
        $auth3 = new Auth($this->settingsInfo);
        $auth3->processResponse();
        $this->assertEmpty($auth3->getAttributes());
        $this->assertEmpty($auth3->getAttributesWithFriendlyName());
        // Duplicated Attribute names
        $_POST['SAMLResponse'] = file_get_contents(TEST_ROOT . '/data/responses/invalids/duplicated_attributes_with_friendly_names.xml.base64');
        $auth4 = new Auth($this->settingsInfo);
        try {
            $auth4->processResponse();
            $this->fail('Saml2\ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertStringContainsString('Found an Attribute element with duplicated FriendlyName', $e->getMessage());
        }
        $_POST['SAMLResponse'] = file_get_contents(TEST_ROOT . '/data/responses/invalids/duplicated_attributes.xml.base64');
        try {
            (new Auth($this->settingsInfo))->processResponse();
            $this->fail('Saml2\ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertStringContainsString('Found an Attribute element with duplicated Name', $e->getMessage());
        }
    }

    /**
     * (phpunit raises an exception when a redirect is executed, the
     * exception is catched and we check that the targetURL is correct)
     * Case redirect without url parameter
     *
     * @covers \Saml2\Auth::redirectTo
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testRedirectTo()
    {
        try {
            $relayState = 'http://sp.example.com';
            $_REQUEST['RelayState'] = $relayState;
            // The Header of the redirect produces an Exception
            $this->auth->redirectTo();
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertStringContainsString('Cannot modify header information', $e->getMessage());
            $this->assertSame($relayState, getUrlFromRedirect($e->getTrace()));
        }
    }

    /**
     * (phpunit raises an exception when a redirect is executed, the
     * exception is catched and we check that the targetURL is correct)
     * Case redirect with url parameter
     *
     * @covers \Saml2\Auth::redirectTo
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testRedirectTowithUrl()
    {
        try {
            $url2 = 'http://sp2.example.com';
            $_REQUEST['RelayState'] = 'http://sp.example.com';
            // The Header of the redirect produces an Exception
            $this->auth->redirectTo($url2);
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertStringContainsString('Cannot modify header information', $e->getMessage());
            $this->assertSame($url2, getUrlFromRedirect($e->getTrace()));
        }
    }

    /**
     * Case No Message, An exception is throw
     *
     * @covers \Saml2\Auth::processSLO
     */
    public function testProcessNoSLO()
    {
        try {
            $this->auth->processSLO(true);
            $this->fail('Error was not raised');
        } catch (Error $e) {
            $this->assertStringContainsString('SAML LogoutRequest/LogoutResponse not found', $e->getMessage());
        }

        $this->assertSame(['invalid_binding'], $this->auth->getErrors());
    }

    /**
     * Case Invalid Logout Response
     *
     * @covers \Saml2\Auth::processSLO
     */
    public function testProcessSLOResponseInvalid()
    {
        $_GET['SAMLResponse'] = file_get_contents(TEST_ROOT . '/data/logout_responses/logout_response_deflated.xml.base64');

        $this->auth->processSLO(true);
        $this->assertEmpty($this->auth->getErrors());

        $this->auth->setStrict(true);
        $this->auth->processSLO(true);
        // The Destination fails
        $this->assertSame(['invalid_logout_response'], $this->auth->getErrors());

        $this->auth->setStrict(false);
        $this->auth->processSLO(true);
        $this->assertEmpty($this->auth->getErrors());
    }

    /**
     * Case Logout Response not sucess
     *
     * @covers \Saml2\Auth::processSLO
     */
    public function testProcessSLOResponseNoSucess()
    {
        // In order to avoid the destination problem
        $_GET['SAMLResponse'] = base64_encode(
            gzdeflate(
                str_replace(
                    'http://stuff.com/endpoints/endpoints/sls.php',
                    Utils::getSelfURLNoQuery(),
                    gzinflate(base64_decode(file_get_contents(TEST_ROOT . '/data/logout_responses/invalids/status_code_responder.xml.base64')))
                )
            )
        );

        $this->auth->setStrict(true);
        $this->auth->processSLO(true);
        $this->assertSame(['logout_not_success'], $this->auth->getErrors());
    }

    /**
     * Case Logout Response with valid and invalid Request ID
     *
     * @covers \Saml2\Auth::processSLO
     */
    public function testProcessSLOResponseRequestId()
    {
        // In order to avoid the destination problem
        $_GET['SAMLResponse'] = base64_encode(
            gzdeflate(
                str_replace(
                    'http://stuff.com/endpoints/endpoints/sls.php',
                    Utils::getSelfURLNoQuery(),
                    gzinflate(base64_decode(file_get_contents(TEST_ROOT . '/data/logout_responses/logout_response_deflated.xml.base64')))
                )
            )
        );
        $this->auth->setStrict(true);
        $this->auth->processSLO(true, 'wrongID');
        $this->assertSame(['invalid_logout_response'], $this->auth->getErrors());

        $this->auth->processSLO(true, 'ONELOGIN_21584ccdfaca36a145ae990442dcd96bfe60151e');
        $this->assertEmpty($this->auth->getErrors());
    }

    /**
     * Case Valid Logout Response
     *
     * @covers \Saml2\Auth::processSLO
     */
    public function testProcessSLOResponseValid()
    {
        // In order to avoid the destination problem
        $_GET['SAMLResponse'] = base64_encode(
            gzdeflate(
                str_replace(
                    'http://stuff.com/endpoints/endpoints/sls.php',
                    Utils::getSelfURLNoQuery(),
                    gzinflate(base64_decode(file_get_contents(TEST_ROOT . '/data/logout_responses/logout_response_deflated.xml.base64')))
                )
            )
        );

        if (!isset($_SESSION)) {
            $_SESSION = [];
        }
        $_SESSION['samltest'] = true;

        $this->auth->setStrict(true);
        $this->auth->processSLO(true);

        $this->assertEmpty($this->auth->getErrors());

        // Session keep alive
        $this->assertTrue(isset($_SESSION['samltest']));
        $this->assertTrue($_SESSION['samltest']);
    }

    /**
     * Case Valid Logout Response, validating deleting the local session
     *
     * @covers \Saml2\Auth::processSLO
     */
    public function testProcessSLOResponseValidDeletingSession()
    {
        if (!isset($_SESSION)) {
            $_SESSION = [];
        }
        $_SESSION['samltest'] = true;

        // In order to avoid the destination problem
        $_GET['SAMLResponse'] = base64_encode(
            gzdeflate(
                str_replace(
                    'http://stuff.com/endpoints/endpoints/sls.php',
                    Utils::getSelfURLNoQuery(),
                    gzinflate(base64_decode(file_get_contents(TEST_ROOT . '/data/logout_responses/logout_response_deflated.xml.base64')))
                )
            )
        );

        $this->auth->setStrict(true);
        $this->auth->processSLO(false);

        $this->assertEmpty($this->auth->getErrors());

        $this->assertFalse(isset($_SESSION['samltest']));
    }

    /**
     * Case Valid Logout Response, validating deleting the local session
     *
     * @covers \Saml2\Auth::processSLO
     */
    public function testProcessSLOResponseValidDeletingSessionCallback()
    {
        if (!isset($_SESSION)) {
            $_SESSION = [];
        }
        $_SESSION['samltest'] = true;

        // In order to avoid the destination problem
        $_GET['SAMLResponse'] = base64_encode(
            gzdeflate(
                str_replace(
                    'http://stuff.com/endpoints/endpoints/sls.php',
                    Utils::getSelfURLNoQuery(),
                    gzinflate(base64_decode(file_get_contents(TEST_ROOT . '/data/logout_responses/logout_response_deflated.xml.base64')))
                )
            )
        );

        $this->auth->setStrict(true);
        $this->auth->processSLO(false, null, false, function () {
            $_SESSION['samltest'] = false;
        });

        $this->assertEmpty($this->auth->getErrors());

        $this->assertTrue(isset($_SESSION['samltest']));
        $this->assertFalse($_SESSION['samltest']);
    }

    /**
     * Case Invalid Logout Request
     *
     * @covers \Saml2\Auth::processSLO
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testProcessSLORequestInvalidValid()
    {
        $_GET['SAMLRequest'] = file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request_deflated.xml.base64');

        $targetUrl = $this->auth->processSLO(true, null, false, null, true);
        $parsedQuery = getParamsFromUrl($targetUrl);

        $this->assertEmpty($this->auth->getErrors());
        $this->assertStringContainsString($this->settingsInfo['idp']['singleLogoutService']['url'], $targetUrl);
        $this->assertArrayHasKey('SAMLResponse', $parsedQuery);
        $this->assertArrayNotHasKey('RelayState', $parsedQuery);

        $this->auth->setStrict(true);
        $this->auth->processSLO(true);
        // Fail due destination missmatch
        $this->assertSame(['invalid_logout_request'], $this->auth->getErrors());

        $this->auth->setStrict(false);
        $targetUrl = $this->auth->processSLO(true, null, false, null, true);
        $parsedQuery = getParamsFromUrl($targetUrl);

        $this->assertEmpty($this->auth->getErrors());
        $this->assertStringContainsString($this->settingsInfo['idp']['singleLogoutService']['url'], $targetUrl);
        $this->assertArrayHasKey('SAMLResponse', $parsedQuery);
        $this->assertArrayNotHasKey('RelayState', $parsedQuery);
    }

    /**
     * Case Logout Request NotOnOrAfter failed
     *
     * @covers \Saml2\Auth::processSLO
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testProcessSLORequestNotOnOrAfterFailed()
    {
        // In order to avoid the destination problem
        $_GET['SAMLRequest'] = base64_encode(
            gzdeflate(
                str_replace(
                    'http://stuff.com/endpoints/endpoints/sls.php',
                    Utils::getSelfURLNoQuery(),
                    gzinflate(base64_decode(file_get_contents(TEST_ROOT . '/data/logout_requests/invalids/not_after_failed.xml.base64')))
                )
            )
        );

        $this->auth->setStrict(true);
        $this->auth->processSLO(true);
        $this->assertSame(['invalid_logout_request'], $this->auth->getErrors());
    }

    /**
     * Case Valid Logout Request, validating that the local session is deleted,
     * a LogoutResponse is created and a redirection executed
     *
     * @covers \Saml2\Auth::processSLO
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testProcessSLORequestDeletingSession()
    {
        // In order to avoid the destination problem
        $_GET['SAMLRequest'] = base64_encode(
            gzdeflate(
                str_replace(
                    'http://stuff.com/endpoints/endpoints/sls.php',
                    Utils::getSelfURLNoQuery(),
                    gzinflate(base64_decode(file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request_deflated.xml.base64')))
                )
            )
        );

        if (!isset($_SESSION)) {
            $_SESSION = [];
        }
        $_SESSION['samltest'] = true;

        try {
            $this->auth->setStrict(true);
            $this->auth->processSLO(false);
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertStringContainsString('Cannot modify header information', $e->getMessage());
            $targetUrl = getUrlFromRedirect($e->getTrace());
            $parsedQuery = getParamsFromUrl($targetUrl);

            $this->assertStringContainsString($this->settingsInfo['idp']['singleLogoutService']['url'], $targetUrl);
            $this->assertArrayHasKey('SAMLResponse', $parsedQuery);
            $this->assertArrayNotHasKey('RelayState', $parsedQuery);

            // Session is not alive
            $this->assertFalse(isset($_SESSION['samltest']));
        }

        $_SESSION['samltest'] = true;

        try {
            $this->auth->setStrict(true);
            $this->auth->processSLO(true);
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertStringContainsString('Cannot modify header information', $e->getMessage());
            $targetUrl = getUrlFromRedirect($e->getTrace());
            $parsedQuery = getParamsFromUrl($targetUrl);

            $this->assertStringContainsString($this->settingsInfo['idp']['singleLogoutService']['url'], $targetUrl);
            $this->assertArrayHasKey('SAMLResponse', $parsedQuery);
            $this->assertArrayNotHasKey('RelayState', $parsedQuery);

            // Session is alive
            $this->assertTrue(isset($_SESSION['samltest']));
            $this->assertTrue($_SESSION['samltest']);
        }
    }

    /**
     * Case Valid Logout Request, validating that the local session is
     * deleted with callback, a LogoutResponse is created and
     * a redirection executed
     *
     * @covers \Saml2\Auth::processSLO
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testProcessSLORequestDeletingSessionCallback()
    {
        // In order to avoid the destination problem
        $_GET['SAMLRequest'] = base64_encode(
            gzdeflate(
                str_replace(
                    'http://stuff.com/endpoints/endpoints/sls.php',
                    Utils::getSelfURLNoQuery(),
                    gzinflate(base64_decode(file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request_deflated.xml.base64')))
                )
            )
        );

        if (!isset($_SESSION)) {
            $_SESSION = [];
        }
        $_SESSION['samltest'] = true;

        try {
            $this->auth->setStrict(true);
            $this->auth->processSLO(false, null, false, function () {
                $_SESSION['samltest'] = false;
            });
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertStringContainsString('Cannot modify header information', $e->getMessage());
            $targetUrl = getUrlFromRedirect($e->getTrace());
            $parsedQuery = getParamsFromUrl($targetUrl);

            $this->assertStringContainsString($this->settingsInfo['idp']['singleLogoutService']['url'], $targetUrl);
            $this->assertArrayHasKey('SAMLResponse', $parsedQuery);
            $this->assertArrayNotHasKey('RelayState', $parsedQuery);

            if (getenv("TRAVIS")) {
                // Can't test that on TRAVIS
                $this->markTestSkipped("Can't test that on TRAVIS");
            } else {
                // Session is alive
                $this->assertTrue(isset($_SESSION['samltest']));
                // But has been modified
                $this->assertFalse($_SESSION['samltest']);
            }
        }
    }

    /**
     * Case Valid Logout Request, validating the relayState,
     * a LogoutResponse is created and a redirection executed
     *
     * @covers \Saml2\Auth::processSLO
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testProcessSLORequestRelayState()
    {
        // In order to avoid the destination problem
        $_GET['SAMLRequest'] = base64_encode(
            gzdeflate(
                str_replace(
                    'http://stuff.com/endpoints/endpoints/sls.php',
                    Utils::getSelfURLNoQuery(),
                    gzinflate(base64_decode(file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request_deflated.xml.base64')))
                )
            )
        );
        $_GET['RelayState'] = 'http://relaystate.com';

        try {
            $this->auth->setStrict(true);
            $this->auth->processSLO(false);
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertStringContainsString('Cannot modify header information', $e->getMessage());
            $targetUrl = getUrlFromRedirect($e->getTrace());
            $parsedQuery = getParamsFromUrl($targetUrl);

            $this->assertStringContainsString($this->settingsInfo['idp']['singleLogoutService']['url'], $targetUrl);
            $this->assertArrayHasKey('SAMLResponse', $parsedQuery);
            $this->assertArrayHasKey('RelayState', $parsedQuery);
            $this->assertSame('http://relaystate.com', $parsedQuery['RelayState']);
        }
    }

    /**
     * Case Valid Logout Request, validating the relayState,
     * a signed LogoutResponse is created and a redirection executed
     *
     * @covers \Saml2\Auth::processSLO
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testProcessSLORequestSignedResponse()
    {
        $settingsInfo = require TEST_ROOT . '/settings/settings1.php';

        $settingsInfo['security']['logoutResponseSigned'] = true;

        $auth = new Auth($settingsInfo);

        // In order to avoid the destination problem
        $_GET['SAMLRequest'] = base64_encode(
            gzdeflate(
                str_replace(
                    'http://stuff.com/endpoints/endpoints/sls.php',
                    Utils::getSelfURLNoQuery(),
                    gzinflate(base64_decode(file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request_deflated.xml.base64')))
                )
            )
        );
        $_GET['RelayState'] = 'http://relaystate.com';

        try {
            $auth->setStrict(true);
            $auth->processSLO(false);
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertStringContainsString('Cannot modify header information', $e->getMessage());
            $targetUrl = getUrlFromRedirect($e->getTrace());
            $parsedQuery = getParamsFromUrl($targetUrl);

            $this->assertStringContainsString($settingsInfo['idp']['singleLogoutService']['url'], $targetUrl);
            $this->assertArrayHasKey('SAMLResponse', $parsedQuery);
            $this->assertArrayHasKey('RelayState', $parsedQuery);
            $this->assertArrayHasKey('SigAlg', $parsedQuery);
            $this->assertArrayHasKey('Signature', $parsedQuery);
            $this->assertSame('http://relaystate.com', $parsedQuery['RelayState']);
            $this->assertSame(XMLSecurityKey::RSA_SHA1, $parsedQuery['SigAlg']);
        }
    }

    /**
     * Case Login with no parameters. An AuthnRequest is built an redirection executed
     *
     * @covers \Saml2\Auth::login
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testLogin()
    {
        try {
            // The Header of the redirect produces an Exception
            $this->auth->login();
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertStringContainsString('Cannot modify header information', $e->getMessage());
            $targetUrl = getUrlFromRedirect($e->getTrace());
            $parsedQuery = getParamsFromUrl($targetUrl);

            $this->assertStringContainsString($this->settingsInfo['idp']['singleSignOnService']['url'], $targetUrl);
            $this->assertArrayHasKey('SAMLRequest', $parsedQuery);
            $this->assertArrayHasKey('RelayState', $parsedQuery);
            $this->assertSame($parsedQuery['RelayState'], Utils::getSelfRoutedURLNoQuery());
        }
    }

    /**
     * Case Login with relayState. An AuthnRequest is built. GET with SAMLRequest,
     * and RelayState. A redirection is executed
     *
     * @covers \Saml2\Auth::login
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testLoginWithRelayState()
    {
        try {
            $relayState = 'http://sp.example.com';
            // The Header of the redirect produces an Exception
            $this->auth->login($relayState);
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertStringContainsString('Cannot modify header information', $e->getMessage());
            $targetUrl = getUrlFromRedirect($e->getTrace());
            $parsedQuery = getParamsFromUrl($targetUrl);

            $this->assertStringContainsString($this->settingsInfo['idp']['singleSignOnService']['url'], $targetUrl);
            $this->assertArrayHasKey('SAMLRequest', $parsedQuery);
            $this->assertArrayHasKey('RelayState', $parsedQuery);
            $this->assertSame($relayState, $parsedQuery['RelayState']);
        }
    }

    /**
     * Case Login with $elaySate and $parameters. An AuthnRequest is built. GET with
     * SAMLRequest, RelayState and extra parameters in the GET. A redirection is executed
     *
     * @covers \Saml2\Auth::login
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testLoginWithRelayStateAndParameters()
    {
        try {
            $relayState = 'http://sp.example.com';
            $parameters = ['test1' => 'value1', 'test2' => 'value2'];

            // The Header of the redirect produces an Exception
            $this->auth->login($relayState, $parameters);
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertStringContainsString('Cannot modify header information', $e->getMessage());
            $targetUrl = getUrlFromRedirect($e->getTrace());
            $parsedQuery = getParamsFromUrl($targetUrl);

            $this->assertStringContainsString($this->settingsInfo['idp']['singleSignOnService']['url'], $targetUrl);
            $this->assertArrayHasKey('SAMLRequest', $parsedQuery);
            $this->assertArrayHasKey('RelayState', $parsedQuery);
            $this->assertSame($relayState, $parsedQuery['RelayState']);
            $this->assertArrayHasKey('test1', $parsedQuery);
            $this->assertArrayHasKey('test2', $parsedQuery);
            $this->assertSame($parameters['test1'], $parsedQuery['test1']);
            $this->assertSame($parameters['test2'], $parsedQuery['test2']);
        }
    }

    /**
     * Case Login signed. An AuthnRequest signed is built an redirect executed
     *
     * @covers \Saml2\Auth::login
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testLoginSigned()
    {
        $settingsInfo = require TEST_ROOT . '/settings/settings1.php';

        $settingsInfo['security']['authnRequestsSigned'] = true;

        try {
            // The Header of the redirect produces an Exception
            $returnTo = 'http://example.com/returnto';
            (new Auth($settingsInfo))->login($returnTo);
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertStringContainsString('Cannot modify header information', $e->getMessage());
            $targetUrl = getUrlFromRedirect($e->getTrace());
            $parsedQuery = getParamsFromUrl($targetUrl);

            $this->assertStringContainsString($settingsInfo['idp']['singleSignOnService']['url'], $targetUrl);
            $this->assertArrayHasKey('SAMLRequest', $parsedQuery);
            $this->assertArrayHasKey('RelayState', $parsedQuery);
            $this->assertArrayHasKey('SigAlg', $parsedQuery);
            $this->assertArrayHasKey('Signature', $parsedQuery);
            $this->assertSame($returnTo, $parsedQuery['RelayState']);
            $this->assertSame(XMLSecurityKey::RSA_SHA1, $parsedQuery['SigAlg']);
        }
    }

    /**
     * Case Login with no parameters. A AuthN Request is built with ForceAuthn and redirect executed
     *
     * @covers \Saml2\Auth::login
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testLoginForceAuthN()
    {
        $settingsInfo = require TEST_ROOT . '/settings/settings1.php';

        $settingsInfo['security']['authnRequestsSigned'] = true;

        $auth = new Auth($settingsInfo);

        try {
            // The Header of the redirect produces an Exception
            $auth->login('http://example.com/returnto');
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertStringContainsString('Cannot modify header information', $e->getMessage());
            $targetUrl = getUrlFromRedirect($e->getTrace());
            $parsedQuery = getParamsFromUrl($targetUrl);

            $this->assertStringContainsString($settingsInfo['idp']['singleSignOnService']['url'], $targetUrl);
            $this->assertArrayHasKey('SAMLRequest', $parsedQuery);
            $this->assertStringNotContainsString('ForceAuthn="true"', gzinflate(base64_decode($parsedQuery['SAMLRequest'])));
        }

        try {
            // The Header of the redirect produces an Exception
            $auth->login('http://example.com/returnto', [], false, false);
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertStringContainsString('Cannot modify header information', $e->getMessage());
            $targetUrl2 = getUrlFromRedirect($e->getTrace());
            $parsedQuery2 = getParamsFromUrl($targetUrl2);

            $this->assertStringContainsString($settingsInfo['idp']['singleSignOnService']['url'], $targetUrl2);
            $this->assertArrayHasKey('SAMLRequest', $parsedQuery2);
            $this->assertStringNotContainsString('ForceAuthn="true"', gzinflate(base64_decode($parsedQuery2['SAMLRequest'])));
        }

        try {
            // The Header of the redirect produces an Exception
            $auth->login('http://example.com/returnto', [], true, false);
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertStringContainsString('Cannot modify header information', $e->getMessage());
            $targetUrl3 = getUrlFromRedirect($e->getTrace());
            $parsedQuery3 = getParamsFromUrl($targetUrl3);

            $this->assertStringContainsString($settingsInfo['idp']['singleSignOnService']['url'], $targetUrl3);
            $this->assertArrayHasKey('SAMLRequest', $parsedQuery3);
            $this->assertStringContainsString('ForceAuthn="true"', gzinflate(base64_decode($parsedQuery3['SAMLRequest'])));
        }
    }

    /**
     * Case Login with no parameters. A AuthN Request is built with IsPassive and redirect executed
     *
     * @covers \Saml2\Auth::login
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testLoginIsPassive()
    {
        $settingsInfo = require TEST_ROOT . '/settings/settings1.php';

        $settingsInfo['security']['authnRequestsSigned'] = true;

        $auth = new Auth($settingsInfo);

        try {
            // The Header of the redirect produces an Exception
            $auth->login('http://example.com/returnto');
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertStringContainsString('Cannot modify header information', $e->getMessage());
            $targetUrl = getUrlFromRedirect($e->getTrace());
            $parsedQuery = getParamsFromUrl($targetUrl);

            $this->assertStringContainsString($settingsInfo['idp']['singleSignOnService']['url'], $targetUrl);
            $this->assertArrayHasKey('SAMLRequest', $parsedQuery);
            $this->assertStringNotContainsString('IsPassive="true"', gzinflate(base64_decode($parsedQuery['SAMLRequest'])));
        }

        try {
            // The Header of the redirect produces an Exception
            $auth->login('http://example.com/returnto', [], false, false);
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertStringContainsString('Cannot modify header information', $e->getMessage());
            $targetUrl2 = getUrlFromRedirect($e->getTrace());
            $parsedQuery2 = getParamsFromUrl($targetUrl2);

            $this->assertStringContainsString($settingsInfo['idp']['singleSignOnService']['url'], $targetUrl2);
            $this->assertArrayHasKey('SAMLRequest', $parsedQuery2);
            $this->assertStringNotContainsString('IsPassive="true"', gzinflate(base64_decode($parsedQuery2['SAMLRequest'])));
        }

        try {
            // The Header of the redirect produces an Exception
            $auth->login('http://example.com/returnto', [], false, true);
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertStringContainsString('Cannot modify header information', $e->getMessage());
            $targetUrl3 = getUrlFromRedirect($e->getTrace());
            $parsedQuery3 = getParamsFromUrl($targetUrl3);

            $this->assertStringContainsString($settingsInfo['idp']['singleSignOnService']['url'], $targetUrl3);
            $this->assertArrayHasKey('SAMLRequest', $parsedQuery3);
            $this->assertStringContainsString('IsPassive="true"', gzinflate(base64_decode($parsedQuery3['SAMLRequest'])));
        }
    }

    /**
     * Case Login with no parameters. A AuthN Request is built with and without NameIDPolicy
     *
     * @covers \Saml2\Auth::login
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testLoginNameIDPolicy()
    {
        $settingsInfo = require TEST_ROOT . '/settings/settings1.php';

        $auth = new Auth($settingsInfo);

        try {
            // The Header of the redirect produces an Exception
            $auth->login('http://example.com/returnto', [], false, false, false, false);
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertStringContainsString('Cannot modify header information', $e->getMessage());
            $targetUrl = getUrlFromRedirect($e->getTrace());
            $parsedQuery = getParamsFromUrl($targetUrl);

            $this->assertStringContainsString($settingsInfo['idp']['singleSignOnService']['url'], $targetUrl);
            $this->assertArrayHasKey('SAMLRequest', $parsedQuery);
            $this->assertStringNotContainsString('<samlp:NameIDPolicy', gzinflate(base64_decode($parsedQuery['SAMLRequest'])));
        }

        try {
            // The Header of the redirect produces an Exception
            $auth->login('http://example.com/returnto', [], false, false, false, true);
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertStringContainsString('Cannot modify header information', $e->getMessage());
            $targetUrl2 = getUrlFromRedirect($e->getTrace());
            $parsedQuery2 = getParamsFromUrl($targetUrl2);

            $this->assertStringContainsString($settingsInfo['idp']['singleSignOnService']['url'], $targetUrl2);
            $this->assertArrayHasKey('SAMLRequest', $parsedQuery2);
            $this->assertStringContainsString('<samlp:NameIDPolicy', gzinflate(base64_decode($parsedQuery2['SAMLRequest'])));
        }

        try {
            // The Header of the redirect produces an Exception
            $auth->login('http://example.com/returnto');
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertStringContainsString('Cannot modify header information', $e->getMessage());
            $targetUrl3 = getUrlFromRedirect($e->getTrace());
            $parsedQuery3 = getParamsFromUrl($targetUrl3);

            $this->assertStringContainsString($settingsInfo['idp']['singleSignOnService']['url'], $targetUrl3);
            $this->assertArrayHasKey('SAMLRequest', $parsedQuery3);
            $this->assertStringContainsString('<samlp:NameIDPolicy', gzinflate(base64_decode($parsedQuery3['SAMLRequest'])));
        }
    }

    /**
     * Case Logout with no parameters. A logout Request is built and redirect executed
     *
     * @covers \Saml2\Auth::logout
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testLogout()
    {
        try {
            // The Header of the redirect produces an Exception
            $this->auth->logout();
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertStringContainsString('Cannot modify header information', $e->getMessage());
            $targetUrl = getUrlFromRedirect($e->getTrace());
            $parsedQuery = getParamsFromUrl($targetUrl);

            $this->assertStringContainsString($this->settingsInfo['idp']['singleLogoutService']['url'], $targetUrl);
            $this->assertArrayHasKey('SAMLRequest', $parsedQuery);
            $this->assertArrayHasKey('RelayState', $parsedQuery);
            $this->assertSame($parsedQuery['RelayState'], Utils::getSelfRoutedURLNoQuery());
        }
    }

    /**
     * Case Logout with relayState. A logout Request is build. GET with SAMLRequest,
     * RelayState. A redirection is executed
     *
     * @covers \Saml2\Auth::logout
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testLogoutWithRelayState()
    {
        try {
            $relayState = 'http://sp.example.com';
            // The Header of the redirect produces an Exception
            $this->auth->logout($relayState);
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertStringContainsString('Cannot modify header information', $e->getMessage());
            $targetUrl = getUrlFromRedirect($e->getTrace());
            $parsedQuery = getParamsFromUrl($targetUrl);

            $this->assertStringContainsString($this->settingsInfo['idp']['singleLogoutService']['url'], $targetUrl);
            $this->assertArrayHasKey('SAMLRequest', $parsedQuery);
            $this->assertArrayHasKey('RelayState', $parsedQuery);
            $this->assertSame($relayState, $parsedQuery['RelayState']);
        }
    }

    /**
     * Case Logout with relayState + parameters. A logout Request is build. GET with SAMLRequest,
     * RelayState and extra parameters. A redirection is executed
     *
     * @covers \Saml2\Auth::logout
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testLogoutWithRelayStateAndParameters()
    {
        try {
            $relayState = 'http://sp.example.com';
            $parameters = ['test1' => 'value1', 'test2' => 'value2'];

            // The Header of the redirect produces an Exception
            $this->auth->logout($relayState, $parameters);
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertStringContainsString('Cannot modify header information', $e->getMessage());
            $targetUrl = getUrlFromRedirect($e->getTrace());
            $parsedQuery = getParamsFromUrl($targetUrl);

            $this->assertStringContainsString($this->settingsInfo['idp']['singleLogoutService']['url'], $targetUrl);
            $this->assertArrayHasKey('SAMLRequest', $parsedQuery);
            $this->assertArrayHasKey('RelayState', $parsedQuery);
            $this->assertSame($relayState, $parsedQuery['RelayState']);
            $this->assertArrayHasKey('test1', $parsedQuery);
            $this->assertArrayHasKey('test2', $parsedQuery);
            $this->assertSame($parameters['test1'], $parsedQuery['test1']);
            $this->assertSame($parameters['test2'], $parsedQuery['test2']);
        }
    }

    /**
     * Case Logout with relayState + NameID + SessionIndex. A logout Request is build. GET with SAMLRequest.
     * A redirection is executed
     *
     * @covers \Saml2\Auth::logout
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testLogoutWithNameIdAndSessionIndex()
    {
        try {
            // The Header of the redirect produces an Exception
            $this->auth->logout(null, [], 'my_name_id', '_51be37965feb5579d803141076936dc2e9d1d98ebf');
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertStringContainsString('Cannot modify header information', $e->getMessage());
            $targetUrl = getUrlFromRedirect($e->getTrace());
            $parsedQuery = getParamsFromUrl($targetUrl);

            $this->assertStringContainsString($this->settingsInfo['idp']['singleLogoutService']['url'], $targetUrl);
            $this->assertArrayHasKey('SAMLRequest', $parsedQuery);
        }
    }

    /**
     * Case nameID loaded after process SAML Response
     *
     * @covers \Saml2\Auth::logout
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testLogoutNameID()
    {
        $_POST['SAMLResponse'] = file_get_contents(TEST_ROOT . '/data/responses/valid_response.xml.base64');
        $this->auth->processResponse();
        try {
            $this->auth->logout();
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertStringContainsString('Cannot modify header information', $e->getMessage());
            $targetUrl = getUrlFromRedirect($e->getTrace());
            $parsedQuery = getParamsFromUrl($targetUrl);

            $this->assertStringContainsString($this->settingsInfo['idp']['singleLogoutService']['url'], $targetUrl);
            $this->assertArrayHasKey('SAMLRequest', $parsedQuery);

            $this->assertSame($this->auth->getNameId(), LogoutRequest::getNameId(gzinflate(base64_decode($parsedQuery['SAMLRequest']))));
        }
    }

    /**
     * Case Logout signed. A logout Request signed in
     * the assertion is built and redirect executed
     *
     * @covers \Saml2\Auth::logout
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testLogoutSigned()
    {
        $settingsInfo = require TEST_ROOT . '/settings/settings1.php';

        $settingsInfo['security']['logoutRequestSigned'] = true;

        try {
            // The Header of the redirect produces an Exception
            $returnTo = 'http://example.com/returnto';
            (new Auth($settingsInfo))->logout($returnTo);
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertStringContainsString('Cannot modify header information', $e->getMessage());
            $targetUrl = getUrlFromRedirect($e->getTrace());
            $parsedQuery = getParamsFromUrl($targetUrl);

            $this->assertStringContainsString($settingsInfo['idp']['singleLogoutService']['url'], $targetUrl);
            $this->assertArrayHasKey('SAMLRequest', $parsedQuery);
            $this->assertArrayHasKey('RelayState', $parsedQuery);
            $this->assertArrayHasKey('SigAlg', $parsedQuery);
            $this->assertArrayHasKey('Signature', $parsedQuery);
            $this->assertSame($returnTo, $parsedQuery['RelayState']);
            $this->assertSame(XMLSecurityKey::RSA_SHA1, $parsedQuery['SigAlg']);
        }
    }

    /**
     * Case IdP no SLO endpoint.
     *
     * @covers \Saml2\Auth::logout
     */
    public function testLogoutNoSLO()
    {
        $settingsInfo = require TEST_ROOT . '/settings/settings1.php';

        unset($settingsInfo['idp']['singleLogoutService']);

        $auth = new Auth($settingsInfo);

        try {
            $auth->logout('http://example.com/returnto');
            $this->fail('Error was not raised');
        } catch (Error $e) {
            $this->assertStringContainsString('The IdP does not support Single Log Out', $e->getMessage());
        }
    }

    /**
     * @covers \Saml2\Auth::setStrict
     */
    public function testSetStrict()
    {
        $settingsInfo = require TEST_ROOT . '/settings/settings1.php';
        $settingsInfo['strict'] = false;

        $auth = new Auth($settingsInfo);

        $this->assertFalse($auth->getSettings()->isStrict());

        $auth->setStrict(true);
        $this->assertTrue($auth->getSettings()->isStrict());

        $auth->setStrict(false);
        $this->assertFalse($auth->getSettings()->isStrict());
    }

    /**
     * @covers \Saml2\Auth::buildRequestSignature
     * @covers \Saml2\Auth::buildMessageSignature
     */
    public function testBuildRequestSignature()
    {
        $this->assertSame(
            'CqdIlbO6GieeJFV+PYqyqz1QVJunQXdZZl+ZyIby9O3/eMJM0XHi+TWReRrpgNxKkbmmvx5fp/t7mphbLiVYNMgGINEaaa/OfoaGwU9GM5YCVULA2t7qZBel1yrIXGMxijJizB7UPR2ZMo4G+Wdhx1zbmbB0GYM0A27w6YCe/+k=',
            $this->auth->buildRequestSignature(
                file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request_deflated.xml.base64'),
                'http://relaystate.com'
            )
        );
    }

    /**
     * @covers \Saml2\Auth::buildResponseSignature
     * @covers \Saml2\Auth::buildMessageSignature
     */
    public function testBuildResponseSignature()
    {
        $this->assertSame(
            'fFGaOuO/2+ch/xlwU5o7iS6R+v2quWchLAtiDyQTxStFQZKY1NsBs/eYIin2Meq7oTl1Ks6tpT6JshH5OwhPh/08K7M2oa6FIKb99cjg+jIJ/WwpuJ5h9SH0XXP8y3RLhCxLIomHDsBOGQK8WvOlXFUg+9nvOaEMNi6raUWrGhA=',
            $this->auth->buildResponseSignature(file_get_contents(TEST_ROOT . '/data/logout_responses/logout_response_deflated.xml.base64'), 'http://relaystate.com')
        );
    }

    /**
     * Tests that we can get the Id of the SAMLResponse and
     * the assertion processed and the NotOnOrAfter value
     *
     * @covers \Saml2\Auth::getLastMessageId()
     * @covers \Saml2\Auth::getLastAssertionId()
     * @covers \Saml2\Auth::getLastAssertionNotOnOrAfter()
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testGetInfoFromLastResponseReceived()
    {
        $_POST['SAMLResponse'] = base64_encode(file_get_contents(TEST_ROOT . '/data/responses/signed_message_response.xml'));
        $this->auth->processResponse();
        $this->assertEmpty($this->auth->getErrors());
        $this->assertSame('pfxc3d2b542-0f7e-8767-8e87-5b0dc6913375', $this->auth->getLastMessageId());
        $this->assertSame('_cccd6024116641fe48e0ae2c51220d02755f96c98d', $this->auth->getLastAssertionId());
        $this->assertNull($this->auth->getLastAssertionNotOnOrAfter());

        $_POST['SAMLResponse'] = file_get_contents(TEST_ROOT . '/data/responses/valid_response.xml.base64');
        $this->auth->processResponse();
        $this->assertEmpty($this->auth->getErrors());
        $this->assertSame('pfx42be40bf-39c3-77f0-c6ae-8bf2e23a1a2e', $this->auth->getLastMessageId());
        $this->assertSame('pfx57dfda60-b211-4cda-0f63-6d5deb69e5bb', $this->auth->getLastAssertionId());
        $this->assertNull($this->auth->getLastAssertionNotOnOrAfter());

        // NotOnOrAfter is calculated with strict = true
        // If invalid, response id and assertion id are not obtained

        $settingsInfo = require TEST_ROOT . '/settings/settings1.php';

        $settingsInfo['strict'] = true;
        $auth = new Auth($settingsInfo);

        $auth->processResponse();
        $this->assertNotEmpty($auth->getErrors());
        $this->assertNull($auth->getLastMessageId());
        $this->assertNull($auth->getLastMessageId());
        $this->assertNull($auth->getLastAssertionId());
        $this->assertNull($auth->getLastAssertionNotOnOrAfter());

        Utils::setSelfProtocol('https');
        Utils::setSelfHost('pitbulk.no-ip.org');
        $auth->processResponse();
        $this->assertEmpty($auth->getErrors());
        $this->assertSame('pfx42be40bf-39c3-77f0-c6ae-8bf2e23a1a2e', $auth->getLastMessageId());
        $this->assertSame('pfx57dfda60-b211-4cda-0f63-6d5deb69e5bb', $auth->getLastAssertionId());
        $this->assertSame(2671081021, $auth->getLastAssertionNotOnOrAfter());
    }

    /**
     * Tests that we can get the Id of the LogoutRequest processed
     *
     * @covers \Saml2\Auth::getLastMessageId()
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testGetIdFromLastLogoutRequest()
    {
        $_GET['SAMLRequest'] = base64_encode(file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request.xml'));
        $this->auth->processSLO(false, null, false, null, true);
        $this->assertSame('ONELOGIN_21584ccdfaca36a145ae990442dcd96bfe60151e', $this->auth->getLastMessageId());
    }

    /**
     * Tests that we can get the Id of the LogoutResponse processed
     *
     * @covers \Saml2\Auth::getLastMessageId()
     */
    public function testGetIdFromLastLogoutResponse()
    {
        $_GET['SAMLResponse'] = file_get_contents(TEST_ROOT . '/data/logout_responses/logout_response.xml.base64');
        $this->auth->processSLO(false, null, false, null, true);
        $this->assertSame('_f9ee61bd9dbf63606faa9ae3b10548d5b3656fb859', $this->auth->getLastMessageId());
    }
}
