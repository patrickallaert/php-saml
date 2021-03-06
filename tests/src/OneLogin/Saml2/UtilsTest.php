<?php

namespace Saml2\Tests;

use DOMDocument;
use DOMElement;
use DOMXPath;
use Exception;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use Saml2\Constants;
use Saml2\Settings;
use Saml2\Utils;
use Saml2\ValidationError;

/**
 * @backupStaticAttributes enabled
 */
class UtilsTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @covers \Saml2\Utils::loadXML
     */
    public function testLoadXML()
    {
        $dom = new DOMDocument();
        Utils::loadXML($dom, file_get_contents(TEST_ROOT . '/data/metadata/noentity_metadata_settings1.xml'));
        $xpath = new DOMXPath($dom);
        $xpath->registerNamespace('md', Constants::NS_MD);
        $this->assertSame(Constants::NAMEID_UNSPECIFIED, $xpath->query("//md:NameIDFormat")->item(0)->textContent);

        $dom = new DOMDocument();
        Utils::loadXML($dom, file_get_contents(TEST_ROOT . '/data/metadata/metadata_settings1.xml'));
        $xpath = new DOMXPath($dom);
        $xpath->registerNamespace('md', Constants::NS_MD);
        $this->assertSame(Constants::NAMEID_UNSPECIFIED, $xpath->query("//md:NameIDFormat")->item(0)->textContent);
    }

    /**
     * @covers \Saml2\Utils::loadXML
     */
    public function testLoadInvalidXML()
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage("An error occurred while loading the XML data");
        Utils::loadXML(new DOMDocument(), '<xml><EntityDescriptor>');
    }

    /**
     * @covers \Saml2\Utils::loadXML
     */
    public function testXMLAttacks()
    {
        $dom = new DOMDocument();

        try {
            Utils::loadXML(
                $dom,
                '<?xml version="1.0" encoding="ISO-8859-1"?>
                 <!DOCTYPE foo [  
                 <!ELEMENT foo ANY >
                 <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>'
            );
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertSame('Detected use of DOCTYPE/ENTITY in XML, disabled to prevent XXE/XEE attacks', $e->getMessage());
        }

        try {
            Utils::loadXML(
                $dom,
                '<?xml version="1.0"?>
                 <!DOCTYPE results [
                   <!ELEMENT results (result+)>
                   <!ELEMENT result (#PCDATA)>
                 ]>
                 <results>
                   <result>test</result>
                 </results>'
            );
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertSame('Detected use of DOCTYPE/ENTITY in XML, disabled to prevent XXE/XEE attacks', $e->getMessage());
        }

        try {
            Utils::loadXML(
                $dom,
                '<?xml version="1.0"?>
                 <!DOCTYPE results [<!ENTITY harmless "completely harmless">]>
                 <results>
                   <result>This result is &harmless;</result>
                 </results>'
            );
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertSame('Detected use of DOCTYPE/ENTITY in XML, disabled to prevent XXE/XEE attacks', $e->getMessage());
        }

        try {
            Utils::loadXML(
                $dom,
                mb_convert_encoding(
                    '<?xml version="1.0" encoding="UTF-16"?>
                     <!DOCTYPE results [<!ENTITY harmless "completely harmless">]>
                     <results>
                       <result>This result is &harmless;</result>
                     </results>',
                    'UTF-16'
                )
            );
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertSame('Detected use of DOCTYPE/ENTITY in XML, disabled to prevent XXE/XEE attacks', $e->getMessage());
        }
    }

    /**
     * @covers \Saml2\Utils::validateXML
     */
    public function testValidateXML()
    {
        $dom = new DOMDocument();
        Utils::loadXML($dom, file_get_contents(TEST_ROOT . '/data/metadata/noentity_metadata_settings1.xml'));
        $this->assertFalse(Utils::validateXML($dom, 'saml-schema-metadata-2.0.xsd'));

        $dom = new DOMDocument();
        Utils::loadXML($dom, file_get_contents(TEST_ROOT . '/data/metadata/expired_metadata_settings1.xml'));
        $this->assertTrue(Utils::validateXML($dom, 'saml-schema-metadata-2.0.xsd'));

        $dom = new DOMDocument();
        Utils::loadXML($dom, file_get_contents(TEST_ROOT . '/data/metadata/metadata_settings1.xml'));
        $this->assertTrue(Utils::validateXML($dom, 'saml-schema-metadata-2.0.xsd'));

        $dom = new DOMDocument();
        Utils::loadXML($dom, file_get_contents(TEST_ROOT . '/data/metadata/metadata_bad_order_settings1.xml'));
        $this->assertFalse(Utils::validateXML($dom, 'saml-schema-metadata-2.0.xsd'));

        $dom = new DOMDocument();
        Utils::loadXML($dom, file_get_contents(TEST_ROOT . '/data/metadata/signed_metadata_settings1.xml'));
        $this->assertTrue(Utils::validateXML($dom, 'saml-schema-metadata-2.0.xsd'));
    }

    /**
     * @covers \Saml2\Utils::formatCert
     */
    public function testFormatCert()
    {
        $settingsInfo = require TEST_ROOT . '/settings/settings2.php';

        $cert = $settingsInfo['idp']['x509cert'];
        $this->assertStringNotContainsString('-----BEGIN CERTIFICATE-----', $cert);
        $this->assertStringNotContainsString('-----END CERTIFICATE-----', $cert);
        $this->assertSame(860, strlen($cert));

        $formatedCert1 = Utils::formatCert($cert);
        $this->assertStringContainsString('-----BEGIN CERTIFICATE-----', $formatedCert1);
        $this->assertStringContainsString('-----END CERTIFICATE-----', $formatedCert1);

        $this->assertSame($formatedCert1, Utils::formatCert($cert, true));

        $formatedCert3 = Utils::formatCert($cert, false);
        $this->assertStringNotContainsString('-----BEGIN CERTIFICATE-----', $formatedCert3);
        $this->assertStringNotContainsString('-----END CERTIFICATE-----', $formatedCert3);
        $this->assertSame(860, strlen($cert));

        $cert2 = $settingsInfo['sp']['x509cert'];
        $this->assertStringNotContainsString('-----BEGIN CERTIFICATE-----', $cert);
        $this->assertStringNotContainsString('-----END CERTIFICATE-----', $cert);
        $this->assertSame(860, strlen($cert));

        $formatedCert4 = Utils::formatCert($cert);
        $this->assertStringContainsString('-----BEGIN CERTIFICATE-----', $formatedCert4);
        $this->assertStringContainsString('-----END CERTIFICATE-----', $formatedCert4);

        $this->assertSame($formatedCert4, Utils::formatCert($cert, true));

        $formatedCert6 = Utils::formatCert($cert, false);
        $this->assertStringNotContainsString('-----BEGIN CERTIFICATE-----', $formatedCert6);
        $this->assertStringNotContainsString('-----END CERTIFICATE-----', $formatedCert6);
        $this->assertSame(860, strlen($cert2));
    }

    /**
     * @covers \Saml2\Utils::formatPrivateKey
     */
    public function testFormatPrivateKey()
    {
        $settingsInfo = require TEST_ROOT . '/settings/settings2.php';

        $key = $settingsInfo['sp']['privateKey'];

        $this->assertStringNotContainsString('-----BEGIN RSA PRIVATE KEY-----', $key);
        $this->assertStringNotContainsString('-----END RSA PRIVATE KEY-----', $key);
        $this->assertSame(816, strlen($key));

        $formatedKey1 = Utils::formatPrivateKey($key);
        $this->assertStringContainsString('-----BEGIN RSA PRIVATE KEY-----', $formatedKey1);
        $this->assertStringContainsString('-----END RSA PRIVATE KEY-----', $formatedKey1);

        $this->assertSame($formatedKey1, Utils::formatPrivateKey($key, true));

        $formatedKey3 = Utils::formatPrivateKey($key, false);

        $this->assertStringNotContainsString('-----BEGIN RSA PRIVATE KEY-----', $formatedKey3);
        $this->assertStringNotContainsString('-----END RSA PRIVATE KEY-----', $formatedKey3);
        $this->assertSame(816, strlen($key));
    }

    /**
     * @covers \Saml2\Utils::redirect
     */
    public function testRedirect()
    {
        // Check relative and absolute
        $hostname = Utils::getSelfHost();
        $url = "http://$hostname/example";
        $this->assertSame(Utils::redirect($url, [], true), Utils::redirect('/example', [], true));

        try {
            Utils::redirect("ftp://$hostname/example", [], true);
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertStringContainsString('Redirect to invalid URL', $e->getMessage());
        }

        // Review parameter prefix
        $parameters1 = ['value1' => 'a'];

        $this->assertSame("http://$hostname/example?value1=a", Utils::redirect($url, $parameters1, true));

        // Check that accept http/https and reject other protocols
        $this->assertSame("https://$hostname/example?test=true&value1=a", Utils::redirect("https://$hostname/example?test=true", $parameters1, true));

        // Review parameters
        $this->assertSame(
            "http://$hostname/example?alphavalue=a&numvalue[]=1&numvalue[]=2&testing",
            Utils::redirect(
                $url,
                [
                    'alphavalue' => 'a',
                    'numvalue' => ['1', '2'],
                    'testing' => null,
                ],
                true
            )
        );

        $this->assertSame(
            "http://$hostname/example?alphavalue=a&numvaluelist[]=",
            Utils::redirect(
                $url,
                [
                    'alphavalue' => 'a',
                    'emptynumvaluelist' => [],
                    'numvaluelist' => [''],
                ],
                true
            )
        );
    }

    /**
     * @covers \Saml2\Utils::setSelfHost
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testSetselfhost()
    {
        $_SERVER['HTTP_HOST'] = 'example.org';
        $this->assertSame('example.org', Utils::getSelfHost());

        Utils::setSelfHost('example.com');
        $this->assertSame('example.com', Utils::getSelfHost());
    }

    /**
     * @covers \Saml2\Utils::setProxyVars()
     * @covers \Saml2\Utils::getProxyVars()
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testProxyvars()
    {
        $this->assertFalse(Utils::getProxyVars());

        Utils::setProxyVars(true);
        $this->assertTrue(Utils::getProxyVars());

        $_SERVER['HTTP_X_FORWARDED_PROTO'] = 'https';
        $_SERVER['SERVER_PORT'] = '80';

        $this->assertTrue(Utils::isHTTPS());

        Utils::setProxyVars(false);
        $this->assertFalse(Utils::isHTTPS());
    }

    /**
     * @covers \Saml2\Utils::getSelfHost
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testGetselfhost()
    {
        $this->assertSame(gethostname(), Utils::getSelfHost());

        $_SERVER['SERVER_NAME'] = 'example.com';
        $this->assertSame('example.com', Utils::getSelfHost());

        $_SERVER['HTTP_HOST'] = 'example.org';
        $this->assertSame('example.org', Utils::getSelfHost());

        $_SERVER['HTTP_HOST'] = 'example.org:443';
        $this->assertSame('example.org', Utils::getSelfHost());

        $_SERVER['HTTP_HOST'] = 'example.org:ok';
        $this->assertSame('example.org', Utils::getSelfHost());

        $_SERVER['HTTP_X_FORWARDED_HOST'] = 'example.net';
        $this->assertNotSame('example.net', Utils::getSelfHost());

        Utils::setProxyVars(true);
        $this->assertSame('example.net', Utils::getSelfHost());
    }

    /**
     * @covers \Saml2\Utils::isHTTPS
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testisHTTPS()
    {
        $this->assertFalse(Utils::isHTTPS());

        $_SERVER['HTTPS'] = 'on';
        $this->assertTrue(Utils::isHTTPS());

        unset($_SERVER['HTTPS']);
        $this->assertFalse(Utils::isHTTPS());
        $_SERVER['HTTP_HOST'] = 'example.com:443';
        $this->assertTrue(Utils::isHTTPS());
    }

    /**
     * @covers \Saml2\Utils::getSelfURLhost
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testGetselfurlhostdoubleport()
    {
        Utils::setProxyVars(true);
        $_SERVER['HTTP_HOST'] = 'example.com:8080';
        $_SERVER['HTTP_X_FORWARDED_PORT'] = 82;
        $this->assertSame('http://example.com:82', Utils::getSelfURLhost());

        $_SERVER['HTTP_HOST'] = 'example.com:ok';
        $_SERVER['HTTP_X_FORWARDED_PORT'] = 82;
        $this->assertSame('http://example.com:82', Utils::getSelfURLhost());
    }

    /**
     * @covers \Saml2\Utils::getSelfPort
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testGetselfPort()
    {
        $this->assertNull(Utils::getSelfPort());

        $_SERVER['HTTP_HOST'] = 'example.org:ok';
        $this->assertNull(Utils::getSelfPort());

        $_SERVER['HTTP_HOST'] = 'example.org:8080';
        $this->assertSame(8080, Utils::getSelfPort());

        $_SERVER["SERVER_PORT"] = 80;
        $this->assertSame(80, Utils::getSelfPort());

        $_SERVER["HTTP_X_FORWARDED_PORT"] = 443;
        $this->assertSame(80, Utils::getSelfPort());

        Utils::setProxyVars(true);
        $this->assertSame(443, Utils::getSelfPort());

        Utils::setSelfPort(8080);
        $this->assertSame(8080, Utils::getSelfPort());
    }

    /**
     * @covers \Saml2\Utils::setSelfProtocol
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testSetselfprotocol()
    {
        $this->assertFalse(Utils::isHTTPS());

        Utils::setSelfProtocol('https');
        $this->assertTrue(Utils::isHTTPS());
    }

    /**
     * @covers \Saml2\Utils::setBaseURLPath
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testSetBaseURLPath()
    {
        $this->assertNull(Utils::getBaseURLPath());

        Utils::setBaseURLPath('sp');
        $this->assertSame('/sp/', Utils::getBaseURLPath());

        Utils::setBaseURLPath('sp/');
        $this->assertSame('/sp/', Utils::getBaseURLPath());

        Utils::setBaseURLPath('/sp');
        $this->assertSame('/sp/', Utils::getBaseURLPath());

        Utils::setBaseURLPath('/sp/');
        $this->assertSame('/sp/', Utils::getBaseURLPath());
    }

    /**
     * @covers \Saml2\Utils::setBaseURL
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testSetBaseURL()
    {
        $_SERVER['HTTP_HOST'] = 'sp.example.com';
        $_SERVER['HTTPS'] = 'https';
        $_SERVER['REQUEST_URI'] = '/example1/route.php?x=test';
        $_SERVER['QUERY_STRING'] = '?x=test';
        $_SERVER['SCRIPT_NAME'] = '/example1/route.php';
        unset($_SERVER['PATH_INFO']);

        Utils::setBaseURL("no-valid-url");
        $this->assertSame('sp.example.com', Utils::getSelfHost());
        $this->assertNull(Utils::getSelfPort());
        $this->assertNull(Utils::getBaseURLPath());

        $this->assertSame('https://sp.example.com/example1/route.php', Utils::getSelfURLNoQuery());
        $this->assertSame('https://sp.example.com/example1/route.php', Utils::getSelfRoutedURLNoQuery());
        $this->assertSame('https://sp.example.com/example1/route.php?x=test', Utils::getSelfURL());

        Utils::setBaseURL("http://anothersp.example.com:81/example2/");
        $expectedRoutedUrlNQ2 = 'http://anothersp.example.com:81/example2/route.php';
        $expectedUrl2 = 'http://anothersp.example.com:81/example2/route.php?x=test';

        $this->assertSame('anothersp.example.com', Utils::getSelfHost());
        $this->assertSame(81, Utils::getSelfPort());
        $this->assertSame('/example2/', Utils::getBaseURLPath());

        $this->assertSame('http://anothersp.example.com:81/example2/route.php', Utils::getSelfURLNoQuery());
        $this->assertSame($expectedRoutedUrlNQ2, Utils::getSelfRoutedURLNoQuery());
        $this->assertSame($expectedUrl2, Utils::getSelfURL());

        $_SERVER['PATH_INFO'] = '/test';
        $this->assertSame('http://anothersp.example.com:81/example2/route.php/test', Utils::getSelfURLNoQuery());
        $this->assertSame($expectedRoutedUrlNQ2, Utils::getSelfRoutedURLNoQuery());
        $this->assertSame($expectedUrl2, Utils::getSelfURL());
    }

    /**
     * @covers \Saml2\Utils::getSelfURLhost
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testGetSelfURLhost()
    {
        $hostname = Utils::getSelfHost();

        $this->assertSame("http://$hostname", Utils::getSelfURLhost());

        $_SERVER['SERVER_PORT'] = '80';
        $this->assertSame("http://$hostname", Utils::getSelfURLhost());

        $_SERVER['SERVER_PORT'] = '81';
        $this->assertSame("http://$hostname:81", Utils::getSelfURLhost());

        $_SERVER['SERVER_PORT'] = '443';
        $this->assertSame("https://$hostname", Utils::getSelfURLhost());

        unset($_SERVER['SERVER_PORT']);
        $_SERVER['HTTPS'] = 'on';
        $this->assertSame("https://$hostname", Utils::getSelfURLhost());

        $_SERVER['SERVER_PORT'] = '444';
        $this->assertSame("https://$hostname:444", Utils::getSelfURLhost());

        $_SERVER['SERVER_PORT'] = '443';
        $_SERVER['REQUEST_URI'] = '/onelogin';
        $this->assertSame("https://$hostname", Utils::getSelfURLhost());

        $_SERVER['REQUEST_URI'] = 'https://$hostname/onelogin/sso';
        $this->assertSame("https://$hostname", Utils::getSelfURLhost());
    }

    /**
     * @covers \Saml2\Utils::getSelfURL
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testGetSelfURL()
    {
        $url = Utils::getSelfURLhost();

        $this->assertSame($url, Utils::getSelfURL());

        $_SERVER['REQUEST_URI'] = '/index.php';
        $this->assertSame($url . '/index.php', Utils::getSelfURL());

        $_SERVER['REQUEST_URI'] = '/test/index.php?testing';
        $this->assertSame($url . '/test/index.php?testing', Utils::getSelfURL());

        $_SERVER['REQUEST_URI'] = '/test/index.php?testing';
        $this->assertSame($url . '/test/index.php?testing', Utils::getSelfURL());

        $_SERVER['REQUEST_URI'] = 'https://example.com/testing';
        $this->assertSame($url . '/testing', Utils::getSelfURL());
    }

    /**
     * @covers \Saml2\Utils::getSelfURLNoQuery
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testGetSelfURLNoQuery()
    {
        $url = Utils::getSelfURLhost();
        $url .= $_SERVER['SCRIPT_NAME'];

        $this->assertSame($url, Utils::getSelfURLNoQuery());

        $_SERVER['PATH_INFO'] = '/test';
        $this->assertSame($url . '/test', Utils::getSelfURLNoQuery());
    }

    /**
     * @covers \Saml2\Utils::getSelfRoutedURLNoQuery
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function getSelfRoutedURLNoQuery()
    {
        $url = Utils::getSelfURLhost();
        $_SERVER['REQUEST_URI'] = 'example1/route?x=test';
        $_SERVER['QUERY_STRING'] = '?x=test';

        $url .= 'example1/route';

        $this->assertSame($url, Utils::getSelfRoutedURLNoQuery());
    }

    /**
     * Gets the status of a message
     *
     * @covers \Saml2\Utils::getStatus
     */
    public function testGetStatus()
    {
        $dom = new DOMDocument();
        $dom->loadXML(base64_decode(file_get_contents(TEST_ROOT . '/data/responses/response1.xml.base64')));

        $status = Utils::getStatus($dom);
        $this->assertSame(Constants::STATUS_SUCCESS, $status['code']);

        $dom2 = new DOMDocument();
        $dom2->loadXML(base64_decode(file_get_contents(TEST_ROOT . '/data/responses/invalids/status_code_responder.xml.base64')));

        $status2 = Utils::getStatus($dom2);
        $this->assertSame(Constants::STATUS_RESPONDER, $status2['code']);
        $this->assertEmpty($status2['msg']);

        $dom3 = new DOMDocument();
        $dom3->loadXML(base64_decode(file_get_contents(TEST_ROOT . '/data/responses/invalids/status_code_responer_and_msg.xml.base64')));

        $status3 = Utils::getStatus($dom3);
        $this->assertSame(Constants::STATUS_RESPONDER, $status3['code']);
        $this->assertSame('something_is_wrong', $status3['msg']);

        $domInv = new DOMDocument();
        $domInv->loadXML(base64_decode(file_get_contents(TEST_ROOT . '/data/responses/invalids/no_status.xml.base64')));

        try {
            Utils::getStatus($domInv);
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertSame('Missing Status on response', $e->getMessage());
        }

        $domInv2 = new DOMDocument();
        $domInv2->loadXML(base64_decode(file_get_contents(TEST_ROOT . '/data/responses/invalids/no_status_code.xml.base64')));

        try {
            Utils::getStatus($domInv2);
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertSame('Missing Status Code on response', $e->getMessage());
        }
    }

    /**
     * @covers \Saml2\Utils::parseTime2SAML
     */
    public function testParseTime2SAML()
    {
        $this->assertSame('2013-12-10T04:39:31Z', Utils::parseTime2SAML(1386650371));
    }

    /**
     * @covers \Saml2\Utils::getExpireTime
     */
    public function testGetExpireTime()
    {
        $this->assertNull(Utils::getExpireTime());

        $this->assertNotNull(Utils::getExpireTime('PT1393462294S'));

        $this->assertSame(1418186371, Utils::getExpireTime('PT1393462294S', 1418186371));

        $this->assertNotSame(1418186371, Utils::getExpireTime('PT1393462294S', 1355114371));
    }

    /**
     * @covers \Saml2\Utils::query
     */
    public function testQuery()
    {
        $dom = new DOMDocument();
        $dom->loadXML(base64_decode(file_get_contents(TEST_ROOT . '/data/responses/valid_response.xml.base64')));

        $assertionNodes = Utils::query($dom, '/samlp:Response/saml:Assertion');
        $this->assertSame(1, $assertionNodes->length);
        $assertion = $assertionNodes->item(0);
        assert($assertion instanceof DOMElement);
        $this->assertSame('saml:Assertion', $assertion->tagName);

        $attributeStatementNodes = Utils::query($dom, '/samlp:Response/saml:Assertion/saml:AttributeStatement');
        $this->assertSame(1, $attributeStatementNodes->length);
        $attributeStatement = $attributeStatementNodes->item(0);
        assert($attributeStatement instanceof DOMElement);
        $this->assertSame('saml:AttributeStatement', $attributeStatement->tagName);

        $attributeStatementNodes2 = Utils::query($dom, './saml:AttributeStatement', $assertion);
        $this->assertSame(1, $attributeStatementNodes2->length);
        $this->assertSame($attributeStatement, $attributeStatementNodes2->item(0));

        $signatureResNodes = Utils::query($dom, '/samlp:Response/ds:Signature');
        $this->assertSame(1, $signatureResNodes->length);
        $signatureRes = $signatureResNodes->item(0);
        assert($signatureRes instanceof DOMElement);
        $this->assertSame('ds:Signature', $signatureRes->tagName);

        $signatureNodes = Utils::query($dom, '/samlp:Response/saml:Assertion/ds:Signature');
        $this->assertSame(1, $signatureNodes->length);
        $signature = $signatureNodes->item(0);
        assert($signature instanceof DOMElement);
        $this->assertSame('ds:Signature', $signature->tagName);

        $signatureNodes2 = Utils::query($dom, './ds:Signature', $assertion);
        $this->assertSame(1, $signatureNodes2->length);
        $signature2 = $signatureNodes2->item(0);
        $this->assertSame($signature->textContent, $signature2->textContent);
        $this->assertNotSame($signatureRes->textContent, $signature2->textContent);

        $this->assertSame(0, Utils::query($dom, './ds:SignatureValue', $assertion)->length);

        $this->assertSame(1, Utils::query($dom, './ds:Signature/ds:SignatureValue', $assertion)->length);

        $this->assertSame(1, Utils::query($dom, './/ds:SignatureValue', $assertion)->length);
    }

    /**
     * Adding a SPNameQualifier
     *
     * @covers \Saml2\Utils::generateNameId
     */
    public function testGenerateNameIdWithSPNameQualifier()
    {
        $nameIdValue = 'ONELOGIN_ce998811003f4e60f8b07a311dc641621379cfde';
        $entityId = 'http://stuff.com/endpoints/metadata.php';

        $this->assertSame(
            '<saml:NameID SPNameQualifier="http://stuff.com/endpoints/metadata.php" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">ONELOGIN_ce998811003f4e60f8b07a311dc641621379cfde</saml:NameID>',
            Utils::generateNameId(
                $nameIdValue,
                $entityId,
                Constants::NAMEID_UNSPECIFIED
            )
        );

        $settingsInfo = require TEST_ROOT . '/settings/settings1.php';

        $this->assertStringContainsString(
            '<saml:EncryptedID><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" Type="http://www.w3.org/2001/04/xmlenc#Element"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/><dsig:KeyInfo xmlns:dsig="http://www.w3.org/2000/09/xmldsig#"><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/><xenc:CipherData><xenc:CipherValue>',
            Utils::generateNameId(
                $nameIdValue,
                $entityId,
                Constants::NAMEID_UNSPECIFIED,
                Utils::formatCert($settingsInfo['idp']['x509cert'])
            )
        );
    }

    /**
     * @covers \Saml2\Utils::generateNameId
     */
    public function testGenerateNameIdWithoutFormat()
    {
        $this->assertSame(
            '<saml:NameID>ONELOGIN_ce998811003f4e60f8b07a311dc641621379cfde</saml:NameID>',
            Utils::generateNameId(
                'ONELOGIN_ce998811003f4e60f8b07a311dc641621379cfde',
                null,
                null
            )
        );
    }

    /**
     * @covers \Saml2\Utils::generateNameId
     */
    public function testGenerateNameIdWithoutSPNameQualifier()
    {
        $nameIdValue = 'ONELOGIN_ce998811003f4e60f8b07a311dc641621379cfde';

        $this->assertSame(
            '<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">ONELOGIN_ce998811003f4e60f8b07a311dc641621379cfde</saml:NameID>',
            Utils::generateNameId(
                $nameIdValue,
                null,
                Constants::NAMEID_UNSPECIFIED
            )
        );

        $settingsInfo = require TEST_ROOT . '/settings/settings1.php';

        $this->assertStringContainsString(
            '<saml:EncryptedID><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" Type="http://www.w3.org/2001/04/xmlenc#Element"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/><dsig:KeyInfo xmlns:dsig="http://www.w3.org/2000/09/xmldsig#"><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/><xenc:CipherData><xenc:CipherValue>',
            Utils::generateNameId(
                $nameIdValue,
                null,
                Constants::NAMEID_UNSPECIFIED,
                Utils::formatCert($settingsInfo['idp']['x509cert'])
            )
        );
    }

    /**
     * @covers \Saml2\Utils::deleteLocalSession
     */
    public function testDeleteLocalSession()
    {
        if (getenv("TRAVIS")) {
            // Can't test that on TRAVIS
            $this->markTestSkipped("Can't test that on TRAVIS");
        } else {
            if (!isset($_SESSION)) {
                $_SESSION = [];
            }
            $_SESSION['samltest'] = true;

            $this->assertTrue(isset($_SESSION['samltest']));
            $this->assertTrue($_SESSION['samltest']);

            Utils::deleteLocalSession();
            $this->assertFalse(isset($_SESSION));
            $this->assertFalse(isset($_SESSION['samltest']));

            $prev = error_reporting(0);
            session_start();
            error_reporting($prev);

            $_SESSION['samltest'] = true;
            Utils::deleteLocalSession();
            $this->assertFalse(isset($_SESSION));
            $this->assertFalse(isset($_SESSION['samltest']));
        }
    }

    /**
     * @covers \Saml2\Utils::calculateX509Fingerprint
     */
    public function testCalculateX509Fingerprint()
    {
        $settingsInfo = require TEST_ROOT . '/settings/settings1.php';

        $certPath = TEST_ROOT . '/data/customPath/certs/';

        $cert = file_get_contents($certPath . 'sp.crt');

        $this->assertNull(Utils::calculateX509Fingerprint(file_get_contents($certPath . 'sp.key')));

        $this->assertNull(Utils::calculateX509Fingerprint(""));

        $this->assertNull(Utils::calculateX509Fingerprint($settingsInfo['idp']['x509cert']));

        $this->assertSame('afe71c28ef740bc87425be13a2263d37971da1f9', Utils::calculateX509Fingerprint(Utils::formatCert($settingsInfo['idp']['x509cert'])));

        $this->assertSame('afe71c28ef740bc87425be13a2263d37971da1f9', Utils::calculateX509Fingerprint($cert));

        $this->assertSame('afe71c28ef740bc87425be13a2263d37971da1f9', Utils::calculateX509Fingerprint($cert, 'sha1'));

        $this->assertSame('c51cfa06c7a49767f6eab18238eae1c56708e29264da3d11f538a12cd2c357ba', Utils::calculateX509Fingerprint($cert, 'sha256'));

        $this->assertSame('bc5826e6f9429247254bae5e3c650e6968a36a62d23075eb168134978d88600559c10830c28711b2c29c7947c0c2eb1d', Utils::calculateX509Fingerprint($cert, 'sha384'));

        $this->assertSame('3db29251b97559c67988ea0754cb0573fc409b6f75d89282d57cfb75089539b0bbdb2dcd9ec6e032549ecbc466439d5992e18db2cf5494ca2fe1b2e16f348dff', Utils::calculateX509Fingerprint($cert, 'sha512'));
    }

    /**
     * @covers \Saml2\Utils::formatFingerPrint
     */
    public function testFormatFingerPrint()
    {
        $this->assertSame('afe71c28ef740bc87425be13a2263d37971da1f9', Utils::formatFingerPrint('AF:E7:1C:28:EF:74:0B:C8:74:25:BE:13:A2:26:3D:37:97:1D:A1:F9'));
        $this->assertSame('afe71c28ef740bc87425be13a2263d37971da1f9', Utils::formatFingerPrint('afe71c28ef740bc87425be13a2263d37971da1f9'));
    }

    /**
     * @covers \Saml2\Utils::decryptElement
     */
    public function testDecryptElement()
    {
        $seckey = new XMLSecurityKey(XMLSecurityKey::RSA_1_5, ['type' => 'private']);
        $seckey->loadKey((new Settings(require TEST_ROOT . '/settings/settings1.php'))->getSPkey());

        $domNameIdEnc = new DOMDocument();
        $domNameIdEnc->loadXML(base64_decode(file_get_contents(TEST_ROOT . '/data/responses/response_encrypted_nameid.xml.base64')));
        $encryptedNameIDNode = $domNameIdEnc->getElementsByTagName('EncryptedID')->item(0);
        assert($encryptedNameIDNode instanceof DOMElement);
        $encryptedData = $encryptedNameIDNode->firstChild;
        assert($encryptedData instanceof DOMElement);
        $decryptedNameId = Utils::decryptElement($encryptedData, $seckey);
        $this->assertSame('saml:NameID', $decryptedNameId->tagName);
        $this->assertSame('2de11defd199f8d5bb63f9b7deb265ba5c675c10', $decryptedNameId->nodeValue);

        $domAsssertionEnc = new DOMDocument();
        $domAsssertionEnc->loadXML(base64_decode(file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64')));
        $encryptedAssertionElement = $domAsssertionEnc->getElementsByTagName('EncryptedAssertion')->item(0);
        assert($encryptedAssertionElement instanceof DOMElement);
        $encryptedDataElement = $encryptedAssertionElement->getElementsByTagName('EncryptedData')->item(0);
        assert($encryptedDataElement instanceof DOMElement);
        $this->assertSame(
            'saml:Assertion',
            Utils::decryptElement(
                $encryptedDataElement,
                $seckey
            )->tagName
        );

        try {
            Utils::decryptElement($encryptedNameIDNode, $seckey);
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertStringContainsString('Algorithm mismatch between input key and key in message', $e->getMessage());
        }

        $seckey2 = new XMLSecurityKey(XMLSecurityKey::RSA_1_5, ['type' => 'private']);
        $seckey2->loadKey(file_get_contents(TEST_ROOT . '/data/misc/sp2.key'));
        $decryptedNameId2 = Utils::decryptElement($encryptedData, $seckey2);
        $this->assertSame('saml:NameID', $decryptedNameId2->tagName);
        $this->assertSame('2de11defd199f8d5bb63f9b7deb265ba5c675c10', $decryptedNameId2->nodeValue);

        $seckey3 = new XMLSecurityKey(XMLSecurityKey::RSA_SHA512, ['type' => 'private']);
        $seckey3->loadKey(file_get_contents(TEST_ROOT . '/data/misc/sp2.key'));
        try {
            Utils::decryptElement($encryptedData, $seckey3);
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertStringContainsString('Algorithm mismatch between input key and key used to encrypt  the symmetric key for the message', $e->getMessage());
        }

        $domNameIdEnc2 = new DOMDocument();
        $domNameIdEnc2->loadXML(base64_decode(file_get_contents(TEST_ROOT . '/data/responses/invalids/encrypted_nameID_without_EncMethod.xml.base64')));
        try {
            $encryptedId = $domNameIdEnc2->getElementsByTagName('EncryptedID')->item(0)->firstChild;
            assert($encryptedId instanceof DOMElement);
            Utils::decryptElement($encryptedId, $seckey);
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertStringContainsString('Unable to locate algorithm for this Encrypted Key', $e->getMessage());
        }

        $domNameIdEnc3 = new DOMDocument();
        $domNameIdEnc3->loadXML(base64_decode(file_get_contents(TEST_ROOT . '/data/responses/invalids/encrypted_nameID_without_keyinfo.xml.base64')));
        try {
            $encryptedId = $domNameIdEnc3->getElementsByTagName('EncryptedID')->item(0)->firstChild;
            assert($encryptedId instanceof DOMElement);
            Utils::decryptElement($encryptedId, $seckey);
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertStringContainsString('Algorithm mismatch between input key and key in message', $e->getMessage());
        }
    }

    /**
     * @covers \Saml2\Utils::addSign
     */
    public function testAddSign()
    {
        $settings = new Settings(require TEST_ROOT . '/settings/settings1.php');
        $key = $settings->getSPkey();
        $cert = $settings->getSPcert();

        $xmlAuthn = base64_decode(file_get_contents(TEST_ROOT . '/data/requests/authn_request.xml.base64'));
        $xmlAuthnSigned = Utils::addSign($xmlAuthn, $key, $cert, XMLSecurityKey::RSA_SHA256, XMLSecurityDSig::SHA256);
        $this->assertStringContainsString('<ds:SignatureValue>', $xmlAuthnSigned);
        $this->assertStringContainsString('<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>', $xmlAuthnSigned);
        $this->assertStringContainsString('<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>', $xmlAuthnSigned);
        $res = new DOMDocument();
        $res->loadXML($xmlAuthnSigned);
        $signature = $res->firstChild->firstChild->nextSibling->nextSibling;
        assert($signature instanceof DOMElement);
        $this->assertStringContainsString('ds:Signature', $signature->tagName);

        $xmlAuthnSigned2 = Utils::addSign($xmlAuthn, $key, $cert, XMLSecurityKey::RSA_SHA384, XMLSecurityDSig::SHA512);
        $this->assertStringContainsString('<ds:SignatureValue>', $xmlAuthnSigned2);
        $this->assertStringContainsString('<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"/>', $xmlAuthnSigned2);
        $this->assertStringContainsString('<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>', $xmlAuthnSigned2);
        $res2 = new DOMDocument();
        $res2->loadXML($xmlAuthnSigned2);
        $signature = $res2->firstChild->firstChild->nextSibling->nextSibling;
        assert($signature instanceof DOMElement);
        $this->assertStringContainsString('ds:Signature', $signature->tagName);

        $xmlLogoutReqSigned = Utils::addSign(
            file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request.xml'),
            $key,
            $cert,
            XMLSecurityKey::RSA_SHA256,
            XMLSecurityDSig::SHA512
        );
        $this->assertStringContainsString('<ds:SignatureValue>', $xmlLogoutReqSigned);
        $this->assertStringContainsString('<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>', $xmlLogoutReqSigned);
        $this->assertStringContainsString('<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>', $xmlLogoutReqSigned);
        $res3 = new DOMDocument();
        $res3->loadXML($xmlLogoutReqSigned);
        $signature = $res3->firstChild->firstChild->nextSibling->nextSibling;
        assert($signature instanceof DOMElement);
        $this->assertStringContainsString('ds:Signature', $signature->tagName);

        $xmlLogoutResSigned = Utils::addSign(
            base64_decode(file_get_contents(TEST_ROOT . '/data/logout_responses/logout_response.xml.base64')),
            $key,
            $cert,
            XMLSecurityKey::RSA_SHA256,
            XMLSecurityDSig::SHA512
        );
        $this->assertStringContainsString('<ds:SignatureValue>', $xmlLogoutResSigned);
        $this->assertStringContainsString('<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>', $xmlLogoutResSigned);
        $this->assertStringContainsString('<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>', $xmlLogoutResSigned);
        $res4 = new DOMDocument();
        $res4->loadXML($xmlLogoutResSigned);
        $signature = $res4->firstChild->firstChild->nextSibling->nextSibling;
        assert($signature instanceof DOMElement);
        $this->assertStringContainsString('ds:Signature', $signature->tagName);

        $xmlMetadataSigned = Utils::addSign(
            file_get_contents(TEST_ROOT . '/data/metadata/metadata_settings1.xml'),
            $key,
            $cert,
            XMLSecurityKey::RSA_SHA256,
            XMLSecurityDSig::SHA512
        );
        $this->assertStringContainsString('<ds:SignatureValue>', $xmlMetadataSigned);
        $this->assertStringContainsString('<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>', $xmlMetadataSigned);
        $this->assertStringContainsString('<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>', $xmlMetadataSigned);
        $res5 = new DOMDocument();
        $res5->loadXML($xmlMetadataSigned);
        $signature = $res5->firstChild->firstChild;
        assert($signature instanceof DOMElement);
        $this->assertStringContainsString('ds:Signature', $signature->tagName);
    }

    /**
     * @covers \Saml2\Utils::validateSign
     */
    public function testValidateSign()
    {
        $cert = (new Settings(require TEST_ROOT . '/settings/settings1.php'))->getIdPX509Certificate();
        $fingerprint = Utils::calculateX509Fingerprint($cert);

        $xmlMetadataSigned = new DOMDocument();
        $xmlMetadataSigned->loadXML(file_get_contents(TEST_ROOT . '/data/metadata/signed_metadata_settings1.xml'));
        $this->assertTrue(Utils::validateSign($xmlMetadataSigned, $cert, null, 'sha1', "//ds:Signature", null));
        $this->assertTrue(Utils::validateSign($xmlMetadataSigned, null, $fingerprint, 'sha1', "//ds:Signature", null));
        $this->assertTrue(Utils::validateSign($xmlMetadataSigned, null, $fingerprint, 'sha1', "//ds:Signature", null));
        $this->assertFalse(Utils::validateSign($xmlMetadataSigned, null, $fingerprint, 'sha256', "//ds:Signature", null));
        $this->assertTrue(Utils::validateSign($xmlMetadataSigned, null, Utils::calculateX509Fingerprint($cert, 'sha256'), 'sha256', "//ds:Signature", null));

        $xmlResponseMsgSigned = new DOMDocument();
        $xmlResponseMsgSigned->loadXML(file_get_contents(TEST_ROOT . '/data/responses/signed_message_response.xml'));
        $this->assertTrue(Utils::validateSign($xmlResponseMsgSigned, $cert, null, 'sha1', "//ds:Signature", null));
        $this->assertTrue(Utils::validateSign($xmlResponseMsgSigned, null, $fingerprint, 'sha1', "//ds:Signature", null));

        $xmlResponseAssertSigned = new DOMDocument();
        $xmlResponseAssertSigned->loadXML(base64_decode(file_get_contents(TEST_ROOT . '/data/responses/signed_assertion_response.xml.base64')));
        $this->assertTrue(Utils::validateSign($xmlResponseAssertSigned, $cert, null, 'sha1', "//ds:Signature", null));
        $this->assertTrue(Utils::validateSign($xmlResponseAssertSigned, null, $fingerprint, 'sha1', "//ds:Signature", null));

        $xmlResponseDoubleSigned = new DOMDocument();
        $xmlResponseDoubleSigned->loadXML(base64_decode(file_get_contents(TEST_ROOT . '/data/responses/double_signed_response.xml.base64')));
        $this->assertTrue(Utils::validateSign($xmlResponseDoubleSigned, $cert, null, 'sha1', "//ds:Signature", null));
        $this->assertTrue(Utils::validateSign($xmlResponseDoubleSigned, null, $fingerprint, 'sha1', "//ds:Signature", null));

        $xmlResponseMsgSigned->firstChild->firstChild->nodeValue = 'https://example.com/other-idp';
        try {
            $this->assertFalse(Utils::validateSign($xmlResponseMsgSigned, $cert, null, 'sha1', "//ds:Signature", null));
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertStringContainsString('Reference validation failed', $e->getMessage());
        }

        $this->assertFalse(Utils::validateSign($xmlMetadataSigned, null, 'afe71c34ef740bc87434be13a2263d31271da1f9', 'sha1', "//ds:Signature", null));

        $dom = new DOMDocument();
        $dom->loadXML(base64_decode(file_get_contents(TEST_ROOT . '/data/responses/invalids/no_signature.xml.base64')));
        try {
            $this->assertFalse(Utils::validateSign($dom, $cert, null, 'sha1', "//ds:Signature", null));
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertStringContainsString('Cannot locate Signature Node', $e->getMessage());
        }

        $dom = new DOMDocument();
        $dom->loadXML(base64_decode(file_get_contents(TEST_ROOT . '/data/responses/invalids/no_key.xml.base64')));
        try {
            $this->assertFalse(Utils::validateSign($dom, $cert, null, 'sha1', "//ds:Signature", null));
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertStringContainsString('We have no idea about the key', $e->getMessage());
        }

        $dom = new DOMDocument();
        $dom->loadXML(base64_decode(file_get_contents(TEST_ROOT . '/data/responses/invalids/signature_wrapping_attack.xml.base64')));
        try {
            $this->assertFalse(Utils::validateSign($dom, $cert, null, "sha1", "//ds:Signature", null));
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertStringContainsString('Reference validation failed', $e->getMessage());
        }
    }
}
