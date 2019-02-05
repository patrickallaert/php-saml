<?php

namespace OneLogin\Saml2\Tests;

use OneLogin\Saml2\Error;

class ErrorTest extends \PHPUnit\Framework\TestCase
{
    /**
     * The creation of a deflated SAML Request
     *
     * @covers OneLogin\Saml2\Error
     */
    public function testError()
    {
        $this->assertEquals('test', (new Error('test'))->getMessage());
    }
}
