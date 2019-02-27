<?php

namespace Saml2\Tests;

use Saml2\Error;

class ErrorTest extends \PHPUnit\Framework\TestCase
{
    /**
     * The creation of a deflated SAML Request
     *
     * @covers \Saml2\Error
     */
    public function testError()
    {
        $this->assertSame('test', (new Error('test'))->getMessage());
    }
}
