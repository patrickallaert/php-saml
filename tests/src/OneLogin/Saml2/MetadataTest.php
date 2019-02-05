<?php

namespace OneLogin\Saml2\Tests;

use Exception;
use OneLogin\Saml2\Metadata;
use OneLogin\Saml2\Settings;
use OneLogin\Saml2\Utils;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

class MetadataTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @covers OneLogin\Saml2\Metadata::builder
     */
    public function testBuilder()
    {
        include TEST_ROOT . '/settings/settings1.php';

        $settings = new Settings($settingsInfo);
        $spData = $settings->getSPData();
        $security = $settings->getSecurityData();
        $organization = $settings->getOrganization();
        $contacts = $settings->getContacts();

        $metadata = Metadata::builder($spData, $security['authnRequestsSigned'], $security['wantAssertionsSigned'], null, null, $contacts, $organization);

        $this->assertNotEmpty($metadata);

        $this->assertContains('<md:SPSSODescriptor', $metadata);
        $this->assertContains('entityID="http://stuff.com/endpoints/metadata.php"', $metadata);
        $this->assertContains('AuthnRequestsSigned="false"', $metadata);
        $this->assertContains('WantAssertionsSigned="false"', $metadata);

        $this->assertContains('<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"', $metadata);
        $this->assertContains('Location="http://stuff.com/endpoints/endpoints/acs.php"', $metadata);
        $this->assertContains('<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"', $metadata);
        $this->assertContains('Location="http://stuff.com/endpoints/endpoints/sls.php"', $metadata);

        $this->assertContains('<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>', $metadata);

        $this->assertContains('<md:OrganizationName xml:lang="en-US">sp_test</md:OrganizationName>', $metadata);
        $this->assertContains('<md:ContactPerson contactType="technical">', $metadata);
        $this->assertContains('<md:GivenName>technical_name</md:GivenName>', $metadata);

        $security['authnRequestsSigned'] = true;
        $security['wantAssertionsSigned'] = true;
        unset($spData['singleLogoutService']);

        $metadata2 = Metadata::builder($spData, $security['authnRequestsSigned'], $security['wantAssertionsSigned']);

        $this->assertNotEmpty($metadata2);

        $this->assertContains('AuthnRequestsSigned="true"', $metadata2);
        $this->assertContains('WantAssertionsSigned="true"', $metadata2);

        $this->assertNotContains('<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"', $metadata2);
        $this->assertNotContains(' Location="http://stuff.com/endpoints/endpoints/sls.php"/>', $metadata2);
    }

    /**
     * @covers OneLogin\Saml2\Metadata::builder
     */
    public function testBuilderWithAttributeConsumingService()
    {
        include TEST_ROOT . '/settings/settings3.php';
        $settings = new Settings($settingsInfo);
        $spData = $settings->getSPData();
        $security = $settings->getSecurityData();
        $organization = $settings->getOrganization();
        $contacts = $settings->getContacts();

        $metadata = Metadata::builder($spData, $security['authnRequestsSigned'], $security['wantAssertionsSigned'], null, null, $contacts, $organization);

        $this->assertContains('<md:ServiceName xml:lang="en">Service Name</md:ServiceName>', $metadata);
        $this->assertContains('<md:ServiceDescription xml:lang="en">Service Description</md:ServiceDescription>', $metadata);
        $this->assertContains('<md:RequestedAttribute Name="FirstName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true" />', $metadata);
        $this->assertContains('<md:RequestedAttribute Name="LastName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true" />', $metadata);

        $this->assertInstanceOf('DOMDocument', Utils::validateXML($metadata, 'saml-schema-metadata-2.0.xsd'));
    }

    /**
     * @covers OneLogin\Saml2\Metadata::builder
     */
    public function testBuilderWithAttributeConsumingServiceWithMultipleAttributeValue()
    {
        include TEST_ROOT . '/settings/settings4.php';
        $settings = new Settings($settingsInfo);
        $spData = $settings->getSPData();
        $security = $settings->getSecurityData();
        $organization = $settings->getOrganization();
        $contacts = $settings->getContacts();

        $metadata = Metadata::builder($spData, $security['authnRequestsSigned'], $security['wantAssertionsSigned'], null, null, $contacts, $organization);

        $this->assertContains('<md:ServiceName xml:lang="en">Service Name</md:ServiceName>', $metadata);
        $this->assertContains('<md:ServiceDescription xml:lang="en">Service Description</md:ServiceDescription>', $metadata);
        $this->assertContains('<md:RequestedAttribute Name="urn:oid:0.9.2342.19200300.100.1.1" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="uid" isRequired="true" />', $metadata);
        $this->assertContains('<saml:AttributeValue xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">userType</saml:AttributeValue>', $metadata);
        $this->assertContains('<saml:AttributeValue xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">admin</saml:AttributeValue>', $metadata);

        $this->assertInstanceOf('DOMDocument', Utils::validateXML($metadata, 'saml-schema-metadata-2.0.xsd'));
    }

    /**
     * @covers OneLogin\Saml2\Metadata::signMetadata
     */
    public function testSignMetadata()
    {
        include TEST_ROOT . '/settings/settings1.php';

        $settings = new Settings($settingsInfo);
        $security = $settings->getSecurityData();

        $metadata = Metadata::builder($settings->getSPData(), $security['authnRequestsSigned'], $security['wantAssertionsSigned']);

        $this->assertNotEmpty($metadata);

        $certPath = $settings->getCertPath();
        $key = file_get_contents($certPath . 'sp.key');
        $cert = file_get_contents($certPath . 'sp.crt');

        $signedMetadata = Metadata::signMetadata($metadata, $key, $cert);

        $this->assertContains('<md:SPSSODescriptor', $signedMetadata);
        $this->assertContains('entityID="http://stuff.com/endpoints/metadata.php"', $signedMetadata);
        $this->assertContains('AuthnRequestsSigned="false"', $signedMetadata);
        $this->assertContains('WantAssertionsSigned="false"', $signedMetadata);

        $this->assertContains('<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"', $signedMetadata);
        $this->assertContains('Location="http://stuff.com/endpoints/endpoints/acs.php"', $signedMetadata);
        $this->assertContains('<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"', $signedMetadata);
        $this->assertContains(' Location="http://stuff.com/endpoints/endpoints/sls.php"/>', $signedMetadata);

        $this->assertContains('<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>', $signedMetadata);

        $this->assertContains('<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>', $signedMetadata);
        $this->assertContains('<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>', $signedMetadata);
        $this->assertContains('<ds:Reference', $signedMetadata);
        $this->assertContains('<ds:KeyInfo><ds:X509Data><ds:X509Certificate>', $signedMetadata);

        try {
            Metadata::signMetadata('', $key, $cert);
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertContains('Empty string supplied as input', $e->getMessage());
        }
    }

    /**
     * @covers OneLogin\Saml2\Metadata::signMetadata
     */
    public function testSignMetadataDefaultAlgorithms()
    {
        include TEST_ROOT . '/settings/settings1.php';

        $settings = new Settings($settingsInfo);
        $security = $settings->getSecurityData();

        $certPath = $settings->getCertPath();
        $signedMetadata = Metadata::signMetadata(
            Metadata::builder(
                $settings->getSPData(),
                $security['authnRequestsSigned'],
                $security['wantAssertionsSigned']
            ),
            file_get_contents($certPath . 'sp.key'),
            file_get_contents($certPath . 'sp.crt')
        );

        $this->assertContains('<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>', $signedMetadata);
        $this->assertContains('<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>', $signedMetadata);
    }

    /**
     * @covers OneLogin\Saml2\Metadata::signMetadata
     */
    public function testSignMetadataCustomAlgorithms()
    {
        include TEST_ROOT . '/settings/settings1.php';

        $settings = new Settings($settingsInfo);
        $security = $settings->getSecurityData();

        $certPath = $settings->getCertPath();
        $signedMetadata = Metadata::signMetadata(Metadata::builder($settings->getSPData(), $security['authnRequestsSigned'], $security['wantAssertionsSigned']), file_get_contents($certPath . 'sp.key'), file_get_contents($certPath . 'sp.crt'), XMLSecurityKey::RSA_SHA256, XMLSecurityDSig::SHA512);

        $this->assertContains('<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>', $signedMetadata);
        $this->assertContains('<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>', $signedMetadata);
    }

    /**
     * @covers OneLogin\Saml2\Metadata::addX509KeyDescriptors
     */
    public function testAddX509KeyDescriptors()
    {
        include TEST_ROOT . '/settings/settings1.php';

        $settings = new Settings($settingsInfo);
        $metadata = Metadata::builder($settings->getSPData());

        $this->assertNotContains('<md:KeyDescriptor use="signing"', $metadata);
        $this->assertNotContains('<md:KeyDescriptor use="encryption"', $metadata);

        $cert = file_get_contents($settings->getCertPath() . 'sp.crt');

        $metadataWithDescriptors = Metadata::addX509KeyDescriptors($metadata, $cert);

        $this->assertContains('<md:KeyDescriptor use="signing"', $metadataWithDescriptors);
        $this->assertContains('<md:KeyDescriptor use="encryption"', $metadataWithDescriptors);

        $metadataWithDescriptors = Metadata::addX509KeyDescriptors($metadata, $cert, false);

        $this->assertContains('<md:KeyDescriptor use="signing"', $metadataWithDescriptors);
        $this->assertNotContains('<md:KeyDescriptor use="encryption"', $metadataWithDescriptors);

        $metadataWithDescriptors = Metadata::addX509KeyDescriptors($metadata, $cert, 'foobar');

        $this->assertContains('<md:KeyDescriptor use="signing"', $metadataWithDescriptors);
        $this->assertNotContains('<md:KeyDescriptor use="encryption"', $metadataWithDescriptors);

        try {
            Metadata::addX509KeyDescriptors('', $cert);
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertContains('Error parsing metadata', $e->getMessage());
        }

        libxml_use_internal_errors(true);
        try {
            Metadata::addX509KeyDescriptors(file_get_contents(TEST_ROOT . '/data/metadata/unparsed_metadata.xml'), $cert);
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertContains('Error parsing metadata', $e->getMessage());
        }
    }

    /**
     * Case: Execute 2 addX509KeyDescriptors calls
     *
     * @covers OneLogin\Saml2\Metadata::addX509KeyDescriptors
     */
    public function testAddX509KeyDescriptors2Times()
    {
        include TEST_ROOT . '/settings/settings1.php';

        $settings = new Settings($settingsInfo);
        $spData = $settings->getSPData();

        $metadata = Metadata::builder($spData);

        $this->assertNotContains('<md:KeyDescriptor use="signing"', $metadata);
        $this->assertNotContains('<md:KeyDescriptor use="encryption"', $metadata);

        $cert = file_get_contents($settings->getCertPath() . 'sp.crt');

        $metadata = Metadata::addX509KeyDescriptors($metadata, $cert, false);

        $this->assertEquals(1, substr_count($metadata, "<md:KeyDescriptor"));

        $metadata = Metadata::addX509KeyDescriptors($metadata, $cert, false);

        $this->assertEquals(2, substr_count($metadata, "<md:KeyDescriptor"));

        $metadata2 = Metadata::builder($spData);

        $metadata2 = Metadata::addX509KeyDescriptors($metadata2, $cert);

        $this->assertEquals(2, substr_count($metadata2, "<md:KeyDescriptor"));

        $this->assertEquals(1, substr_count($metadata2, '<md:KeyDescriptor use="signing"'));

        $this->assertEquals(1, substr_count($metadata2, '<md:KeyDescriptor use="encryption"'));

        $metadata2 = Metadata::addX509KeyDescriptors($metadata2, $cert);

        $this->assertEquals(4, substr_count($metadata2, "<md:KeyDescriptor"));

        $this->assertEquals(2, substr_count($metadata2, '<md:KeyDescriptor use="signing"'));

        $this->assertEquals(2, substr_count($metadata2, '<md:KeyDescriptor use="encryption"'));
    }
}
