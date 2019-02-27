<?php

namespace Saml2\Tests;

use Saml2\Response;
use Saml2\Settings;

class SignedResponseTest extends \PHPUnit\Framework\TestCase
{
    /**
     * Case valid signed response, unsigned assertion
     *
     * @covers \Saml2\Response::getNameId
     */
    public function testResponseSignedAssertionNot()
    {
        // The Response is signed, the Assertion is not
        $this->assertSame(
            'someone@example.org',
            (new Response(
                new Settings(require TEST_ROOT . '/settings/settings1.php'),
                base64_encode(file_get_contents(TEST_ROOT . '/data/responses/open_saml_response.xml'))
            ))->getNameId()
        );
    }

    /**
     * Case valid signed response, signed assertion
     *
     * @covers \Saml2\Response::getNameId
     */
    public function testResponseAndAssertionSigned()
    {
        $settingsInfo = require TEST_ROOT . '/settings/settings1.php';

        $settingsInfo['idp']['entityId'] = "https://federate.example.net/saml/saml2/idp/metadata.php";
        $settingsInfo['sp']['entityId'] = "hello.com";
        // Both the Response and the Asseretion are signed
        $this->assertSame(
            'someone@example.com',
            (new Response(
                new Settings($settingsInfo),
                base64_encode(file_get_contents(TEST_ROOT . '/data/responses/simple_saml_php.xml'))
            ))->getNameId()
        );
    }
}
