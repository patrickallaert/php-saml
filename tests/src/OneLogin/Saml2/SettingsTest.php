<?php

namespace Saml2\Tests;

use Exception;
use Saml2\Constants;
use Saml2\Error;
use Saml2\Metadata;
use Saml2\Settings;
use Saml2\Utils;

class SettingsTest extends \PHPUnit\Framework\TestCase
{
    /**
     * Case load setting from array
     *
     * @covers \Saml2\Settings
     */
    public function testLoadSettingsFromArray()
    {
        $settingsInfo = require TEST_ROOT . '/settings/settings1.php';

        $settings = new Settings($settingsInfo);

        $this->assertEmpty($settings->getErrors());

        unset($settingsInfo['sp']['NameIDFormat']);
        unset($settingsInfo['idp']['x509cert']);
        $settingsInfo['idp']['certFingerprint'] = 'afe71c28ef740bc87425be13a2263d37971daA1f9';
        $this->assertEmpty($settings->getErrors());

        unset($settingsInfo['sp']);
        unset($settingsInfo['idp']);

        try {
            new Settings($settingsInfo);
            $this->fail('Error was not raised');
        } catch (Error $e) {
            $this->assertStringContainsString('Invalid array settings', $e->getMessage());
        }

        $this->assertEmpty((new Settings(require TEST_ROOT . '/settings/settings2.php'))->getErrors());
    }

    /**
     * Tests shouldCompressRequests method of Settings.
     *
     * @covers \Saml2\Settings::shouldCompressRequests
     */
    public function testShouldCompressRequests()
    {
        //settings1.php contains a true value for compress => requests.
        $this->assertTrue((new Settings(require TEST_ROOT . '/settings/settings1.php'))->shouldCompressRequests());

        //settings2 contains a false value for compress => requests.
        $this->assertFalse((new Settings(require TEST_ROOT . '/settings/settings2.php'))->shouldCompressRequests());
    }

    /**
     * Tests shouldCompressResponses method of Settings.
     *
     * @covers \Saml2\Settings::shouldCompressResponses
     */
    public function testShouldCompressResponses()
    {
        //settings1.php contains a true value for compress => responses.
        $this->assertTrue((new Settings(require TEST_ROOT . '/settings/settings1.php'))->shouldCompressResponses());

        //settings2 contains a false value for compress => responses.
        $this->assertFalse((new Settings(require TEST_ROOT . '/settings/settings2.php'))->shouldCompressResponses());
    }

    /**
     * @dataProvider invalidCompressSettingsProvider
     * @param string $invalidValue invalidCompressSettingsProvider
     *
     * @covers \Saml2\Settings::__construct
     */
    public function testNonArrayCompressionSettingsCauseSyntaxError($invalidValue)
    {
        try {
            new Settings(["compress" => $invalidValue] + require TEST_ROOT . '/settings/settings1.php');
            $this->fail('Error was not raised');
        } catch (Error $e) {
            $this->assertSame("Invalid array settings: invalid_syntax", $e->getMessage());
            return;
        }

        $this->fail("An Error should have been caught.");
    }

    /**
     * @dataProvider invalidCompressSettingsProvider
     * @param string $invalidValue invalidCompressSettingsProvider
     *
     * @covers \Saml2\Settings::__construct
     */
    public function testThatOnlyBooleansCanBeUsedForCompressionSettings($invalidValue)
    {
        $requestsIsInvalid = false;
        $responsesIsInvalid = false;

        try {
            new Settings(["compress" => ["requests" => $invalidValue]] + require TEST_ROOT . '/settings/settings1.php');
            $this->fail('Error was not raised');
        } catch (Error $e) {
            $this->assertSame("Invalid array settings: 'compress'=>'requests' values must be true or false.", $e->getMessage());
            $requestsIsInvalid = true;
        }

        try {
            new Settings(["compress" => ["responses" => $invalidValue]] + require TEST_ROOT . '/settings/settings1.php');
            $this->fail('Error was not raised');
        } catch (Error $e) {
            $this->assertSame("Invalid array settings: 'compress'=>'responses' values must be true or false.", $e->getMessage());
            $responsesIsInvalid = true;
        }

        $this->assertTrue($requestsIsInvalid);
        $this->assertTrue($responsesIsInvalid);
    }

    public function invalidCompressSettingsProvider()
    {
        return [
            [1],
            [0.1],
            [new \stdClass()],
            ["A random string."],
        ];
    }

    /**
     * @covers \Saml2\Settings::getSPcert
     * @covers \Saml2\Settings::getSPcertNew
     * @covers \Saml2\Settings::getSPkey
     */
    public function testCheckSPCerts()
    {
        $settings = new Settings(require TEST_ROOT . '/settings/settings1.php');

        $settings2 = new Settings(require TEST_ROOT . '/settings/settings2.php');

        $this->assertSame($settings2->getSPkey(), $settings->getSPkey());
        $this->assertSame($settings2->getSPcert(), $settings->getSPcert());
        $this->assertNull($settings2->getSPcertNew());

        $settings3 = new Settings(require TEST_ROOT . '/settings/settings5.php');

        $this->assertSame($settings3->getSPkey(), $settings->getSPkey());
        $this->assertSame($settings3->getSPcert(), $settings->getSPcert());
        $this->assertNotNull($settings3->getSPcertNew());
        $this->assertNotEquals($settings3->getSPcertNew(), $settings3->getSPcert());
    }

    /**
     * The checkSettings method is private and is used at the constructor
     *
     * @covers \Saml2\Settings::__construct
     */
    public function testCheckSettings()
    {
        $settingsInfo = [];

        try {
            new Settings($settingsInfo);
            $this->fail('Error was not raised');
        } catch (Error $e) {
            $this->assertStringContainsString('Invalid array settings: invalid_syntax', $e->getMessage());
        }

        $settingsInfo['strict'] = true;
        try {
            new Settings($settingsInfo);
            $this->fail('Error was not raised');
        } catch (Error $e) {
            $this->assertStringContainsString('idp_not_found', $e->getMessage());
            $this->assertStringContainsString('sp_not_found', $e->getMessage());
        }

        $settingsInfo['idp'] = [];
        $settingsInfo['idp']['x509cert'] = '';
        $settingsInfo['sp'] = [];
        $settingsInfo['sp']['entityID'] = 'SPentityId';
        $settingsInfo['security'] = [];
        $settingsInfo['security']['signMetadata'] = false;
        try {
            new Settings($settingsInfo);
            $this->fail('Error was not raised');
        } catch (Error $e) {
            $this->assertStringContainsString('idp_entityId_not_found', $e->getMessage());
            $this->assertStringContainsString('idp_sso_not_found', $e->getMessage());
            $this->assertStringContainsString('sp_entityId_not_found', $e->getMessage());
            $this->assertStringContainsString('sp_acs_not_found', $e->getMessage());
        }

        $settingsInfo['idp']['entityID'] = 'entityId';
        $settingsInfo['idp']['singleSignOnService']['url'] = 'invalid_value';
        $settingsInfo['idp']['singleLogoutService']['url'] = 'invalid_value';
        $settingsInfo['sp']['assertionConsumerService']['url'] = 'invalid_value';
        $settingsInfo['sp']['singleLogoutService']['url'] = 'invalid_value';
        try {
            new Settings($settingsInfo);
            $this->fail('Error was not raised');
        } catch (Error $e) {
            $this->assertStringContainsString('idp_sso_url_invalid', $e->getMessage());
            $this->assertStringContainsString('idp_slo_url_invalid', $e->getMessage());
            $this->assertStringContainsString('sp_acs_url_invalid', $e->getMessage());
            $this->assertStringContainsString('sp_sls_url_invalid', $e->getMessage());
        }

        $settingsInfo['security']['wantAssertionsSigned'] = true;
        try {
            new Settings($settingsInfo);
            $this->fail('Error was not raised');
        } catch (Error $e) {
            $this->assertStringContainsString('idp_cert_or_fingerprint_not_found_and_required', $e->getMessage());
        }

        $settingsInfo['security']['nameIdEncrypted'] = true;
        try {
            new Settings($settingsInfo);
            $this->fail('Error was not raised');
        } catch (Error $e) {
            $this->assertStringContainsString('idp_cert_not_found_and_required', $e->getMessage());
        }

        $settingsInfo = require TEST_ROOT . '/settings/settings1.php';

        $settingsInfo['security']['signMetadata']['keyFileName'] = 'metadata.key';
        $settingsInfo['organization'] = [
            'en-US' => ['name' => 'miss_information'],
        ];

        $settingsInfo['contactPerson'] = [
            'support' => ['givenName' => 'support_name'],
            'auxiliar' => [
                'givenName' => 'auxiliar_name',
                'emailAddress' => 'auxiliar@example.com',
            ],
        ];

        try {
            new Settings($settingsInfo);
            $this->fail('Error was not raised');
        } catch (Error $e) {
            $this->assertStringContainsString('sp_signMetadata_invalid', $e->getMessage());
            $this->assertStringContainsString('organization_not_enough_data', $e->getMessage());
            $this->assertStringContainsString('contact_type_invalid', $e->getMessage());
        }
    }

    /**
     * Case unsigned metadata
     *
     * @covers \Saml2\Settings::getSPMetadata
     */
    public function testGetSPMetadata()
    {
        $metadata = (new Settings(require TEST_ROOT . '/settings/settings1.php'))->getSPMetadata();

        $this->assertNotEmpty($metadata);

        $this->assertStringContainsString('<md:SPSSODescriptor', $metadata);
        $this->assertStringContainsString('entityID="http://stuff.com/endpoints/metadata.php"', $metadata);
        $this->assertStringContainsString('AuthnRequestsSigned="false"', $metadata);
        $this->assertStringContainsString('WantAssertionsSigned="false"', $metadata);
        $this->assertStringContainsString('<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://stuff.com/endpoints/endpoints/acs.php" index="1"/>', $metadata);
        $this->assertStringContainsString('<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://stuff.com/endpoints/endpoints/sls.php"/>', $metadata);
        $this->assertStringContainsString('<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>', $metadata);
    }

    /**
     * Case with x509certNew
     *
     * @covers \Saml2\Settings::getSPMetadata
     * @dataProvider getSPMetadataWithX509CertNewDataProvider
     */
    public function testGetSPMetadataWithX509CertNew($alwaysIncludeEncryption, $wantNameIdEncrypted, $wantAssertionsEncrypted, $expectEncryptionKeyDescriptor)
    {
        $settingsInfo = require TEST_ROOT . '/settings/settings5.php';
        $settingsInfo['security']['wantNameIdEncrypted'] = $wantNameIdEncrypted;
        $settingsInfo['security']['wantAssertionsEncrypted'] = $wantAssertionsEncrypted;
        $metadata = (new Settings($settingsInfo))->getSPMetadata($alwaysIncludeEncryption);
        $this->assertSame($expectEncryptionKeyDescriptor ? 4 : 2, substr_count($metadata, "<md:KeyDescriptor"));
        // signing KeyDescriptor should always be included
        $this->assertSame(2, substr_count($metadata, '<md:KeyDescriptor use="signing"'));
        $this->assertSame($expectEncryptionKeyDescriptor ? 2 : 0, substr_count($metadata, '<md:KeyDescriptor use="encryption"'));
    }

    public function getSPMetadataWithX509CertNewDataProvider()
    {
        return [
            'settings do not require encryption' => [
                'alwaysIncludeEncryption' => false,
                'wantNameIdEncrypted' => false,
                'wantAssertionsEncrypted' => false,
                'expectEncryptionKeyDescriptor' => false,
            ],
            'wantNameIdEncrypted setting enabled' => [
                'alwaysIncludeEncryption' => false,
                'wantNameIdEncrypted' => true,
                'wantAssertionsEncrypted' => false,
                'expectEncryptionKeyDescriptor' => true,
            ],
            'wantAssertionsEncrypted setting enabled' => [
                'alwaysIncludeEncryption' => false,
                'wantNameIdEncrypted' => false,
                'wantAssertionsEncrypted' => true,
                'expectEncryptionKeyDescriptor' => true,
            ],
            'both settings enabled' => [
                'alwaysIncludeEncryption' => false,
                'wantNameIdEncrypted' => true,
                'wantAssertionsEncrypted' => true,
                'expectEncryptionKeyDescriptor' => true,
            ],
            'metadata requested with encryption' => [
                'alwaysIncludeEncryption' => true,
                'wantNameIdEncrypted' => false,
                'wantAssertionsEncrypted' => false,
                'expectEncryptionKeyDescriptor' => true,
            ],
            'metadata requested with encryption and wantNameIdEncrypted setting enabled' => [
                'alwaysIncludeEncryption' => true,
                'wantNameIdEncrypted' => true,
                'wantAssertionsEncrypted' => false,
                'expectEncryptionKeyDescriptor' => true,
            ],
            'metadata requested with encryption and wantAssertionsEncrypted setting enabled' => [
                'alwaysIncludeEncryption' => true,
                'wantNameIdEncrypted' => false,
                'wantAssertionsEncrypted' => true,
                'expectEncryptionKeyDescriptor' => true,
            ],
            'metadata requested with encryption and both settings enabled' => [
                'alwaysIncludeEncryption' => true,
                'wantNameIdEncrypted' => true,
                'wantAssertionsEncrypted' => true,
                'expectEncryptionKeyDescriptor' => true,
            ],
        ];
    }

    /**
     * Case ValidUntil CacheDuration
     *
     * @covers \Saml2\Settings::getSPMetadata
     */
    public function testGetSPMetadataTiming()
    {
        $settings = new Settings(require TEST_ROOT . '/settings/settings1.php');

        $metadata = $settings->getSPMetadata();
        $this->assertStringContainsString('validUntil="' . gmdate('Y-m-d\TH:i:s\Z', time() + Metadata::TIME_VALID) . '"', $metadata);
        $this->assertStringContainsString('cacheDuration="PT604800S"', $metadata);

        $newValidUntil = 2524668343;
        $metadata2 = $settings->getSPMetadata(false, $newValidUntil, 1209600);
        $this->assertStringContainsString('validUntil="' . gmdate('Y-m-d\TH:i:s\Z', $newValidUntil) . '"', $metadata2);
        $this->assertStringContainsString('cacheDuration="PT1209600S"', $metadata2);
    }

    /**
     * Case signed metadata
     *
     * @covers \Saml2\Settings::getSPMetadata
     */
    public function testGetSPMetadataSigned()
    {
        $settingsInfo = require TEST_ROOT . '/settings/settings1.php';

        if (!isset($settingsInfo['security'])) {
            $settingsInfo['security'] = [];
        }
        $settingsInfo['security']['signMetadata'] = true;
        $settings = new Settings($settingsInfo);

        $metadata = $settings->getSPMetadata();

        $this->assertNotEmpty($metadata);

        $this->assertStringContainsString('<md:SPSSODescriptor', $metadata);
        $this->assertStringContainsString('entityID="http://stuff.com/endpoints/metadata.php"', $metadata);
        $this->assertStringContainsString('AuthnRequestsSigned="false"', $metadata);
        $this->assertStringContainsString('WantAssertionsSigned="false"', $metadata);
        $this->assertStringContainsString('<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://stuff.com/endpoints/endpoints/acs.php" index="1"/>', $metadata);
        $this->assertStringContainsString('<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://stuff.com/endpoints/endpoints/sls.php"/>', $metadata);
        $this->assertStringContainsString('<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>', $metadata);

        $this->assertStringContainsString('<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>', $metadata);
        $this->assertStringContainsString('<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>', $metadata);
        $this->assertStringContainsString('<ds:Reference', $metadata);
        $this->assertStringContainsString('<ds:KeyInfo><ds:X509Data><ds:X509Certificate>', $metadata);

        $settingsInfo = require TEST_ROOT . '/settings/settings2.php';

        if (!isset($settingsInfo['security'])) {
            $settingsInfo['security'] = [];
        }
        $settingsInfo['security']['signMetadata'] = true;

        $metadata2 = (new Settings($settingsInfo))->getSPMetadata();

        $this->assertNotEmpty($metadata2);

        $this->assertStringContainsString('<md:SPSSODescriptor', $metadata2);
        $this->assertStringContainsString('entityID="http://stuff.com/endpoints/metadata.php"', $metadata2);
        $this->assertStringContainsString('AuthnRequestsSigned="false"', $metadata2);
        $this->assertStringContainsString('WantAssertionsSigned="false"', $metadata2);
        $this->assertStringContainsString('<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://stuff.com/endpoints/endpoints/acs.php" index="1"/>', $metadata2);
        $this->assertStringContainsString('<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://stuff.com/endpoints/endpoints/sls.php"/>', $metadata2);
        $this->assertStringContainsString('<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>', $metadata2);

        $this->assertStringContainsString('<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>', $metadata2);
        $this->assertStringContainsString('<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>', $metadata2);
        $this->assertStringContainsString('<ds:Reference', $metadata2);
        $this->assertStringContainsString('<ds:KeyInfo><ds:X509Data><ds:X509Certificate>', $metadata2);
    }

    /**
     * Case signed metadata with specific certs
     *
     * @covers \Saml2\Settings::getSPMetadata
     */
    public function testGetSPMetadataSignedNoMetadataCert()
    {
        $settingsInfo = require TEST_ROOT . '/settings/settings1.php';

        if (!isset($settingsInfo['security'])) {
            $settingsInfo['security'] = [];
        }
        $settingsInfo['security']['signMetadata'] = [];

        try {
            (new Settings($settingsInfo))->getSPMetadata();
            $this->fail('Error was not raised');
        } catch (Error $e) {
            $this->assertStringContainsString('sp_signMetadata_invalid', $e->getMessage());
        }

        $settingsInfo['security']['signMetadata'] = [
            'keyFileName' => 'noexist.key',
            'certFileName' => 'sp.crt',
        ];

        try {
            (new Settings($settingsInfo))->getSPMetadata();
            $this->fail('Error was not raised');
        } catch (Error $e) {
            $this->assertStringContainsString('Private key file not found', $e->getMessage());
        }

        $settingsInfo['security']['signMetadata'] = [
            'keyFileName' => 'sp.key',
            'certFileName' => 'noexist.crt',
        ];
        try {
            (new Settings($settingsInfo))->getSPMetadata();
            $this->fail('Error was not raised');
        } catch (Error $e) {
            $this->assertStringContainsString('Public cert file not found', $e->getMessage());
        }
    }

    /**
     * Case valid metadata
     *
     * @covers \Saml2\Settings::validateMetadata
     */
    public function testValidateMetadata()
    {
        $settings = new Settings(require TEST_ROOT . '/settings/settings1.php');

        $this->assertEmpty($settings->validateMetadata($settings->getSPMetadata()));
    }

    /**
     * Case valid signed metadata
     *
     * @covers \Saml2\Settings::validateMetadata
     */
    public function testValidateSignedMetadata()
    {
        $this->assertEmpty((new Settings(require TEST_ROOT . '/settings/settings1.php'))->validateMetadata(file_get_contents(TEST_ROOT . '/data/metadata/signed_metadata_settings1.xml')));
    }

    /**
     * Case expired metadata
     *
     * @covers \Saml2\Settings::validateMetadata
     */
    public function testValidateMetadataExpired()
    {
        $errors = (new Settings(require TEST_ROOT . '/settings/settings1.php'))->validateMetadata(file_get_contents(TEST_ROOT . '/data/metadata/expired_metadata_settings1.xml'));
        $this->assertNotEmpty($errors);
        $this->assertContains('expired_xml', $errors);
    }

    /**
     * Case no metadata XML
     *
     * @covers \Saml2\Settings::validateMetadata
     */
    public function testValidateMetadataNoXML()
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage("Empty string supplied as input");
        (new Settings(require TEST_ROOT . '/settings/settings1.php'))->validateMetadata('');
    }

    /**
     * Case invalid metadata XML
     *
     * @covers \Saml2\Settings::validateMetadata
     */
    public function testValidateMetadataInvalidXML()
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage("An error occurred while loading the XML data");
        (new Settings(require TEST_ROOT . '/settings/settings1.php'))->validateMetadata('<no xml>');
    }

    /**
     * Case invalid xml metadata: No entity
     *
     * @covers \Saml2\Settings::validateMetadata
     */
    public function testValidateMetadataNoEntity()
    {
        $errors = (new Settings(require TEST_ROOT . '/settings/settings1.php'))->validateMetadata(file_get_contents(TEST_ROOT . '/data/metadata/noentity_metadata_settings1.xml'));
        $this->assertNotEmpty($errors);
        $this->assertContains('invalid_xml', $errors);
    }

    /**
     * Case invalid xml metadata: Wrong order
     *
     * @covers \Saml2\Settings::validateMetadata
     */
    public function testValidateMetadataWrongOrder()
    {
        $errors = (new Settings(require TEST_ROOT . '/settings/settings1.php'))->validateMetadata(file_get_contents(TEST_ROOT . '/data/metadata/metadata_bad_order_settings1.xml'));
        $this->assertNotEmpty($errors);
        $this->assertContains('invalid_xml', $errors);
    }

    /**
     *
     * @covers \Saml2\Settings::getIdPEntityId
     * @covers \Saml2\Settings::getIdPSingleSignOnServiceUrl
     * @covers \Saml2\Settings::getIdPSingleLogoutServiceUrl
     * @covers \Saml2\Settings::getIdPX509Certificate
     * @covers \Saml2\Settings::getIdPMultipleX509SigningCertificate
     */
    public function testGetIdPData()
    {
        $settings = new Settings(require TEST_ROOT . '/settings/settings1.php');

        $this->assertSame('http://idp.example.com/', $settings->getIdPEntityId());
        $this->assertSame('http://idp.example.com/SSOService.php', $settings->getIdPSingleSignOnServiceUrl());
        $this->assertSame('http://idp.example.com/SingleLogoutService.php', $settings->getIdPSingleLogoutServiceUrl());
        $formatedx509cert = Utils::formatCert('MIICgTCCAeoCCQCbOlrWDdX7FTANBgkqhkiG9w0BAQUFADCBhDELMAkGA1UEBhMCTk8xGDAWBgNVBAgTD0FuZHJlYXMgU29sYmVyZzEMMAoGA1UEBxMDRm9vMRAwDgYDVQQKEwdVTklORVRUMRgwFgYDVQQDEw9mZWlkZS5lcmxhbmcubm8xITAfBgkqhkiG9w0BCQEWEmFuZHJlYXNAdW5pbmV0dC5ubzAeFw0wNzA2MTUxMjAxMzVaFw0wNzA4MTQxMjAxMzVaMIGEMQswCQYDVQQGEwJOTzEYMBYGA1UECBMPQW5kcmVhcyBTb2xiZXJnMQwwCgYDVQQHEwNGb28xEDAOBgNVBAoTB1VOSU5FVFQxGDAWBgNVBAMTD2ZlaWRlLmVybGFuZy5ubzEhMB8GCSqGSIb3DQEJARYSYW5kcmVhc0B1bmluZXR0Lm5vMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDivbhR7P516x/S3BqKxupQe0LONoliupiBOesCO3SHbDrl3+q9IbfnfmE04rNuMcPsIxB161TdDpIesLCn7c8aPHISKOtPlAeTZSnb8QAu7aRjZq3+PbrP5uW3TcfCGPtKTytHOge/OlJbo078dVhXQ14d1EDwXJW1rRXuUt4C8QIDAQABMA0GCSqGSIb3DQEBBQUAA4GBACDVfp86HObqY+e8BUoWQ9+VMQx1ASDohBjwOsg2WykUqRXF+dLfcUH9dWR63CtZIKFDbStNomPnQz7nbK+onygwBspVEbnHuUihZq3ZUdmumQqCw4Uvs/1Uvq3orOo/WJVhTyvLgFVK2QarQ4/67OZfHd7R+POBXhophSMv1ZOo');
        $this->assertSame($formatedx509cert, $settings->getIdPX509Certificate());

        $settings = new Settings(require TEST_ROOT . '/settings/settings6.php');

        $signingCertificates = $settings->getIdPMultipleX509SigningCertificate();
        $this->assertSame(Utils::formatCert('MIICbDCCAdWgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBTMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRgwFgYDVQQDDA9pZHAuZXhhbXBsZS5jb20wHhcNMTQwOTIzMTIyNDA4WhcNNDIwMjA4MTIyNDA4WjBTMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRgwFgYDVQQDDA9pZHAuZXhhbXBsZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAOWA+YHU7cvPOrBOfxCscsYTJB+kH3MaA9BFrSHFS+KcR6cw7oPSktIJxUgvDpQbtfNcOkE/tuOPBDoech7AXfvH6d7Bw7xtW8PPJ2mB5Hn/HGW2roYhxmfh3tR5SdwN6i4ERVF8eLkvwCHsNQyK2Ref0DAJvpBNZMHCpS24916/AgMBAAGjUDBOMB0GA1UdDgQWBBQ77/qVeiigfhYDITplCNtJKZTM8DAfBgNVHSMEGDAWgBQ77/qVeiigfhYDITplCNtJKZTM8DAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBDQUAA4GBAJO2j/1uO80E5C2PM6Fk9mzerrbkxl7AZ/mvlbOn+sNZE+VZ1AntYuG8ekbJpJtG1YfRfc7EA9mEtqvv4dhv7zBy4nK49OR+KpIBjItWB5kYvrqMLKBa32sMbgqqUqeF1ENXKjpvLSuPdfGJZA3dNa/+Dyb8GGqWe707zLyc5F8m'), $signingCertificates[0]);
        $this->assertSame($formatedx509cert, $signingCertificates[1]);
        $this->assertSame($formatedx509cert, $settings->getIdPOneEncryptionCertificate());
    }

    /**
     * @covers \Saml2\Settings::getSPEntityId
     * @covers \Saml2\Settings::getSPNameIDFormat
     * @covers \Saml2\Settings::getSPAssertionConsumerServiceUrl
     * @covers \Saml2\Settings::getSPSingleLogoutServiceUrl
     */
    public function testGetSPData()
    {
        $settings = new Settings(require TEST_ROOT . '/settings/settings1.php');

        $this->assertSame('http://stuff.com/endpoints/metadata.php', $settings->getSPEntityId());
        $this->assertSame('http://stuff.com/endpoints/endpoints/acs.php', $settings->getSPAssertionConsumerServiceUrl());
        $this->assertSame('http://stuff.com/endpoints/endpoints/sls.php', $settings->getSPSingleLogoutServiceUrl());
        $this->assertSame(Constants::NAMEID_UNSPECIFIED, $settings->getSPNameIDFormat());
    }

    /**
     * Tests default values of Security advanced settings
     *
     * @covers \Saml2\Settings::getSecurityNameIdEncrypted
     * @covers \Saml2\Settings::getSecurityAuthnRequestsSigned
     * @covers \Saml2\Settings::getSecurityWantLogoutRequestSigned
     * @covers \Saml2\Settings::getSecurityWantLogoutResponseSigned
     * @covers \Saml2\Settings::getSecurityWantMessagesSigned
     * @covers \Saml2\Settings::getSecurityWantAssertionsSigned
     * @covers \Saml2\Settings::getSecurityWantAssertionsEncrypted
     * @covers \Saml2\Settings::getSecurityWantNameIdEncrypted
     * @covers \Saml2\Settings::getSecurityRequestedAuthnContext
     * @covers \Saml2\Settings::getSecurityWantXMLValidation
     * @covers \Saml2\Settings::getSecurityWantNameId
     */
    public function testGetDefaultSecurityValues()
    {
        $settingsInfo = require TEST_ROOT . '/settings/settings1.php';
        unset($settingsInfo['security']);

        $settings = new Settings($settingsInfo);

        $this->assertFalse($settings->getSecurityNameIdEncrypted());
        $this->assertFalse($settings->getSecurityAuthnRequestsSigned());
        $this->assertFalse($settings->getSecurityWantLogoutRequestSigned());
        $this->assertFalse($settings->getSecurityWantLogoutResponseSigned());
        $this->assertFalse($settings->getSecurityWantMessagesSigned());
        $this->assertFalse($settings->getSecurityWantAssertionsSigned());
        $this->assertFalse($settings->getSecurityWantAssertionsEncrypted());
        $this->assertFalse($settings->getSecurityWantNameIdEncrypted());
        $this->assertTrue($settings->getSecurityRequestedAuthnContext());
        $this->assertTrue($settings->getSecurityWantXMLValidation());
        $this->assertTrue($settings->getSecurityWantNameId());
    }

    /**
     * @covers \Saml2\Settings::getContacts
     */
    public function testGetContacts()
    {
        $contacts = (new Settings(require TEST_ROOT . '/settings/settings1.php'))->getContacts();
        $this->assertNotEmpty($contacts);
        $this->assertSame('technical_name', $contacts['technical']['givenName']);
        $this->assertSame('technical@example.com', $contacts['technical']['emailAddress']);
        $this->assertSame('support_name', $contacts['support']['givenName']);
        $this->assertSame('support@example.com', $contacts['support']['emailAddress']);
    }

    /**
     * @covers \Saml2\Settings::getOrganization
     */
    public function testGetOrganization()
    {
        $organization = (new Settings(require TEST_ROOT . '/settings/settings1.php'))->getOrganization();
        $this->assertNotEmpty($organization);
        $this->assertSame('sp_test', $organization['en-US']['name']);
        $this->assertSame('SP test', $organization['en-US']['displayname']);
        $this->assertSame('http://sp.example.com', $organization['en-US']['url']);
    }

    /**
     * @covers \Saml2\Settings::setStrict
     */
    public function testSetStrict()
    {
        $settings = new Settings(require TEST_ROOT . '/settings/settings1.php');
        $this->assertFalse($settings->isStrict());

        $settings->setStrict(true);
        $this->assertTrue($settings->isStrict());

        $settings->setStrict(false);
        $this->assertFalse($settings->isStrict());
    }

    /**
     * @covers \Saml2\Settings::isStrict
     */
    public function testIsStrict()
    {
        $settingsInfo = require TEST_ROOT . '/settings/settings1.php';
        unset($settingsInfo['strict']);

        $this->assertFalse((new Settings($settingsInfo))->isStrict());

        $settingsInfo['strict'] = false;
        $this->assertFalse((new Settings($settingsInfo))->isStrict());

        $settingsInfo['strict'] = true;
        $this->assertTrue((new Settings($settingsInfo))->isStrict());
    }
}
