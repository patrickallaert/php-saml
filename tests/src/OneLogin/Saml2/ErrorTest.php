<?php

namespace OneLogin\Saml2\Tests;

use OneLogin\Saml2\Error;

/**
 * Unit tests for Error class
 */
class ErrorTest extends \PHPUnit\Framework\TestCase
{
    /**
     * Tests the OneLogin\Saml2\Error Constructor.
     * The creation of a deflated SAML Request
     *
     * @covers OneLogin\Saml2\Error
     */
    public function testError()
    {
        $this->assertEquals('test', (new Error('test'))->getMessage());
    }
}
