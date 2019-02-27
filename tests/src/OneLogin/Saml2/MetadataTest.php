<?php

namespace Saml2\Tests;

use DOMDocument;
use Exception;
use Saml2\Metadata;
use Saml2\Settings;
use Saml2\Utils;

class MetadataTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @covers \Saml2\Metadata::builder
     */
    public function testBuilder()
    {
        $settingsData = require TEST_ROOT . '/settings/settings1.php';
        $settings = new Settings($settingsData);
        $metadata = Metadata::builder($settings);

        $this->assertNotEmpty($metadata);

        $this->assertStringContainsString('<md:SPSSODescriptor', $metadata);
        $this->assertStringContainsString('entityID="http://stuff.com/endpoints/metadata.php"', $metadata);
        $this->assertStringContainsString('AuthnRequestsSigned="false"', $metadata);
        $this->assertStringContainsString('WantAssertionsSigned="false"', $metadata);

        $this->assertStringContainsString('<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"', $metadata);
        $this->assertStringContainsString('Location="http://stuff.com/endpoints/endpoints/acs.php"', $metadata);
        $this->assertStringContainsString('<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"', $metadata);
        $this->assertStringContainsString('Location="http://stuff.com/endpoints/endpoints/sls.php"', $metadata);

        $this->assertStringContainsString('<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>', $metadata);

        $this->assertStringContainsString('<md:OrganizationName xml:lang="en-US">sp_test</md:OrganizationName>', $metadata);
        $this->assertStringContainsString('<md:ContactPerson contactType="technical">', $metadata);
        $this->assertStringContainsString('<md:GivenName>technical_name</md:GivenName>', $metadata);

        $settingsData['security']['authnRequestsSigned'] = true;
        $settingsData['security']['wantAssertionsSigned'] = true;

        unset($settingsData['sp']['singleLogoutService']);

        $metadata2 = Metadata::builder($settings = new Settings($settingsData));

        $this->assertNotEmpty($metadata2);

        $this->assertStringContainsString('AuthnRequestsSigned="true"', $metadata2);
        $this->assertStringContainsString('WantAssertionsSigned="true"', $metadata2);

        $this->assertStringNotContainsString('<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"', $metadata2);
        $this->assertStringNotContainsString(' Location="http://stuff.com/endpoints/endpoints/sls.php"/>', $metadata2);
    }

    /**
     * @covers \Saml2\Metadata::builder
     */
    public function testBuilderWithAttributeConsumingService()
    {
        $metadata = Metadata::builder(new Settings(require TEST_ROOT . '/settings/settings3.php'));

        $this->assertStringContainsString('<md:ServiceName xml:lang="en">Service Name</md:ServiceName>', $metadata);
        $this->assertStringContainsString('<md:ServiceDescription xml:lang="en">Service Description</md:ServiceDescription>', $metadata);
        $this->assertStringContainsString('<md:RequestedAttribute Name="FirstName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true" />', $metadata);
        $this->assertStringContainsString('<md:RequestedAttribute Name="LastName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true" />', $metadata);

        $dom = new DOMDocument();
        Utils::loadXML($dom, $metadata);
        $this->assertTrue(Utils::validateXML($dom, 'saml-schema-metadata-2.0.xsd'));
    }

    /**
     * @covers \Saml2\Metadata::builder
     */
    public function testBuilderWithAttributeConsumingServiceWithMultipleAttributeValue()
    {
        $metadata = Metadata::builder(new Settings(require TEST_ROOT . '/settings/settings4.php'));

        $this->assertStringContainsString('<md:ServiceName xml:lang="en">Service Name</md:ServiceName>', $metadata);
        $this->assertStringContainsString('<md:ServiceDescription xml:lang="en">Service Description</md:ServiceDescription>', $metadata);
        $this->assertStringContainsString('<md:RequestedAttribute Name="urn:oid:0.9.2342.19200300.100.1.1" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="uid" isRequired="true" />', $metadata);
        $this->assertStringContainsString('<saml:AttributeValue xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">userType</saml:AttributeValue>', $metadata);
        $this->assertStringContainsString('<saml:AttributeValue xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">admin</saml:AttributeValue>', $metadata);

        $dom = new DOMDocument();
        Utils::loadXML($dom, $metadata);
        $this->assertTrue(Utils::validateXML($dom, 'saml-schema-metadata-2.0.xsd'));
    }

    /**
     * @covers \Saml2\Metadata::addX509KeyDescriptors
     */
    public function testAddX509KeyDescriptors()
    {
        $metadata = Metadata::builder(new Settings(require TEST_ROOT . '/settings/settings1.php'));

        $this->assertStringNotContainsString('<md:KeyDescriptor use="signing"', $metadata);
        $this->assertStringNotContainsString('<md:KeyDescriptor use="encryption"', $metadata);

        $cert = file_get_contents(TEST_ROOT . '/data/customPath/certs/sp.crt');

        $metadataWithDescriptors = Metadata::addX509KeyDescriptors($metadata, $cert);

        $this->assertStringContainsString('<md:KeyDescriptor use="signing"', $metadataWithDescriptors);
        $this->assertStringContainsString('<md:KeyDescriptor use="encryption"', $metadataWithDescriptors);

        $metadataWithDescriptors = Metadata::addX509KeyDescriptors($metadata, $cert, false);

        $this->assertStringContainsString('<md:KeyDescriptor use="signing"', $metadataWithDescriptors);
        $this->assertStringNotContainsString('<md:KeyDescriptor use="encryption"', $metadataWithDescriptors);

        try {
            Metadata::addX509KeyDescriptors('', $cert);
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertStringContainsString('Error parsing metadata', $e->getMessage());
        }

        libxml_use_internal_errors(true);
        try {
            Metadata::addX509KeyDescriptors(file_get_contents(TEST_ROOT . '/data/metadata/unparsed_metadata.xml'), $cert);
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertStringContainsString('Error parsing metadata', $e->getMessage());
        }
    }

    /**
     * Case: Execute 2 addX509KeyDescriptors calls
     *
     * @covers \Saml2\Metadata::addX509KeyDescriptors
     */
    public function testAddX509KeyDescriptors2Times()
    {
        $metadataOriginal = $metadata = Metadata::builder((new Settings(require TEST_ROOT . '/settings/settings1.php')));

        $this->assertStringNotContainsString('<md:KeyDescriptor use="signing"', $metadata);
        $this->assertStringNotContainsString('<md:KeyDescriptor use="encryption"', $metadata);

        $cert = file_get_contents(TEST_ROOT . '/data/customPath/certs/sp.crt');

        $metadata = Metadata::addX509KeyDescriptors($metadata, $cert, false);

        $this->assertSame(1, substr_count($metadata, "<md:KeyDescriptor"));

        $metadata = Metadata::addX509KeyDescriptors($metadata, $cert, false);

        $this->assertSame(2, substr_count($metadata, "<md:KeyDescriptor"));

        $metadata2 = $metadataOriginal;

        $metadata2 = Metadata::addX509KeyDescriptors($metadata2, $cert);

        $this->assertSame(2, substr_count($metadata2, "<md:KeyDescriptor"));

        $this->assertSame(1, substr_count($metadata2, '<md:KeyDescriptor use="signing"'));

        $this->assertSame(1, substr_count($metadata2, '<md:KeyDescriptor use="encryption"'));

        $metadata2 = Metadata::addX509KeyDescriptors($metadata2, $cert);

        $this->assertSame(4, substr_count($metadata2, "<md:KeyDescriptor"));

        $this->assertSame(2, substr_count($metadata2, '<md:KeyDescriptor use="signing"'));

        $this->assertSame(2, substr_count($metadata2, '<md:KeyDescriptor use="encryption"'));
    }
}
