<?php
namespace OneLogin\Saml2;

use DOMDocument;
use DOMElement;
use Exception;

class IdPMetadataParser
{
    /**
     * Get IdP Metadata Info from URL
     *
     * @param string $url                 URL where the IdP metadata is published
     * @param ?string $entityId           Entity Id of the desired IdP, if no
     *                                    entity Id is provided and the XML
     *                                    metadata contains more than one
     *                                    IDPSSODescriptor, the first is returned
     * @param ?string $desiredNameIdFormat If available on IdP metadata, use that nameIdFormat
     */
    public static function parseRemoteXML(
        string $url,
        ?string $entityId = null,
        ?string $desiredNameIdFormat = null,
        string $desiredSSOBinding = Constants::BINDING_HTTP_REDIRECT,
        string $desiredSLOBinding = Constants::BINDING_HTTP_REDIRECT
    ): array {
        try {
            $ch = curl_init($url);

            if ($ch === false) {
                throw new Exception("An unknown error occurred during curl_init");
            }

            curl_setopt_array(
                $ch,
                [
                    CURLOPT_CUSTOMREQUEST => "GET",
                    CURLOPT_RETURNTRANSFER => 1,
                    CURLOPT_FOLLOWLOCATION => 1,
                    CURLOPT_SSL_VERIFYPEER => 0,
                    CURLOPT_FAILONERROR => 1,
                ]
            );

            $xml = curl_exec($ch);
            if ($xml === false) {
                throw new Exception(curl_error($ch), curl_errno($ch));
            }

            return self::parseXML($xml, $entityId, $desiredNameIdFormat, $desiredSSOBinding, $desiredSLOBinding);
        } catch (Exception $e) {
        }
        return [];
    }

    /**
     * Get IdP Metadata Info from File
     *
     * @param string $filepath            File path
     * @param ?string $entityId           Entity Id of the desired IdP, if no
     *                                    entity Id is provided and the XML
     *                                    metadata contains more than one
     *                                    IDPSSODescriptor, the first is returned
     * @param ?string $desiredNameIdFormat If available on IdP metadata, use that nameIdFormat
     */
    public static function parseFileXML(
        string $filepath,
        ?string $entityId = null,
        ?string $desiredNameIdFormat = null,
        string $desiredSSOBinding = Constants::BINDING_HTTP_REDIRECT,
        string $desiredSLOBinding = Constants::BINDING_HTTP_REDIRECT
    ): array {
        $metadataInfo = [];

        try {
            if (file_exists($filepath)) {
                $data = file_get_contents($filepath);
                $metadataInfo = self::parseXML($data, $entityId, $desiredNameIdFormat, $desiredSSOBinding, $desiredSLOBinding);
            }
        } catch (Exception $e) {
        }
        return $metadataInfo;
    }

    /**
     * Get IdP Metadata Info from URL
     *
     * @param string $xml                 XML that contains IdP metadata
     * @param ?string $entityId            Entity Id of the desired IdP, if no
     *                                    entity Id is provided and the XML
     *                                    metadata contains more than one
     *                                    IDPSSODescriptor, the first is returned
     * @param ?string $desiredNameIdFormat If available on IdP metadata, use that nameIdFormat
     * @param string $desiredSSOBinding   Parse specific binding SSO endpoint
     * @param string $desiredSLOBinding   Parse specific binding SLO endpoint
     *
     * @throws Exception
     */
    public static function parseXML(
        string $xml,
        ?string $entityId = null,
        ?string $desiredNameIdFormat = null,
        string $desiredSSOBinding = Constants::BINDING_HTTP_REDIRECT,
        string $desiredSLOBinding = Constants::BINDING_HTTP_REDIRECT
    ): array {
        $metadataInfo = [];

        $dom = new DOMDocument();
        $dom->preserveWhiteSpace = false;
        $dom->formatOutput = true;
        try {
            Utils::loadXML($dom, $xml);

            $idpDescriptorNodes = Utils::query(
                $dom,
                '//md:EntityDescriptor' . (!empty($entityId) ? '[@entityID="' . $entityId . '"]' : '') . '/md:IDPSSODescriptor'
            );

            if ($idpDescriptorNodes->length > 0) {
                $metadataInfo['idp'] = [];

                $idpDescriptor = $idpDescriptorNodes->item(0);
                $parent = $idpDescriptor->parentNode;

                if (empty($entityId) && $parent instanceof DOMElement && $parent->hasAttribute('entityID')) {
                    $entityId = $parent->getAttribute('entityID');
                }

                if (!empty($entityId)) {
                    $metadataInfo['idp']['entityId'] = $entityId;
                }

                $ssoNodes = Utils::query($dom, './md:SingleSignOnService[@Binding="' . $desiredSSOBinding . '"]', $idpDescriptor);
                if ($ssoNodes->length < 1) {
                    $ssoNodes = Utils::query($dom, './md:SingleSignOnService', $idpDescriptor);
                }
                if ($ssoNodes->length > 0) {
                    $firstSSONode = $ssoNodes->item(0);
                    if ($firstSSONode instanceof DOMElement) {
                        $metadataInfo['idp']['singleSignOnService'] = [
                            'url' => $firstSSONode->getAttribute('Location'),
                            'binding' => $firstSSONode->getAttribute('Binding'),
                        ];
                    }
                }

                $sloNodes = Utils::query($dom, './md:SingleLogoutService[@Binding="' . $desiredSLOBinding . '"]', $idpDescriptor);
                if ($sloNodes->length < 1) {
                    $sloNodes = Utils::query($dom, './md:SingleLogoutService', $idpDescriptor);
                }
                if ($sloNodes->length > 0) {
                    $firstSLONode = $sloNodes->item(0);
                    if ($firstSLONode instanceof DOMElement) {
                        $metadataInfo['idp']['singleLogoutService'] = [
                            'url' => $firstSLONode->getAttribute('Location'),
                            'binding' => $firstSLONode->getAttribute('Binding'),
                        ];
                    }
                }

                $metadataInfo['idp']['x509certMulti'] = [];
                $idpInfo['x509certMulti']['signing'] = [];
                foreach (Utils::query(
                    $dom,
                    './md:KeyDescriptor[not(contains(@use, "encryption"))]/ds:KeyInfo/ds:X509Data/ds:X509Certificate',
                    $idpDescriptor
                ) as $keyDescriptorCertSigningNode) {
                    $metadataInfo['idp']['x509certMulti']['signing'][] = Utils::formatCert($keyDescriptorCertSigningNode->nodeValue, false);
                }
                $idpInfo['x509certMulti']['encryption'] = [];

                foreach (Utils::query(
                    $dom,
                    './md:KeyDescriptor[not(contains(@use, "signing"))]/ds:KeyInfo/ds:X509Data/ds:X509Certificate',
                    $idpDescriptor
                ) as $keyDescriptorCertEncryptionNode) {
                    $metadataInfo['idp']['x509certMulti']['encryption'][] = Utils::formatCert($keyDescriptorCertEncryptionNode->nodeValue, false);
                }

                $idpCertdata = $metadataInfo['idp']['x509certMulti'];
                if ((
                        count($idpCertdata) === 1 &&
                        (
                            (isset($idpCertdata['signing']) && count($idpCertdata['signing']) === 1) ||
                            (isset($idpCertdata['encryption']) && count($idpCertdata['encryption']) === 1)
                        )
                    ) ||
                    (
                        isset($idpCertdata['signing'], $idpCertdata['encryption']) &&
                        count($idpCertdata['signing']) === 1 &&
                        count($idpCertdata['encryption']) === 1 &&
                        $idpCertdata['signing'][0] === $idpCertdata['encryption'][0]
                    )
                ) {
                    $metadataInfo['idp']['x509cert'] = $metadataInfo['idp']['x509certMulti']['signing'][0] ??
                        $metadataInfo['idp']['x509certMulti']['encryption'][0];
                    unset($metadataInfo['idp']['x509certMulti']);
                }

                $nameIdFormatNodes = Utils::query($dom, './md:NameIDFormat', $idpDescriptor);
                if ($nameIdFormatNodes->length > 0) {
                    $metadataInfo['sp']['NameIDFormat'] = $nameIdFormatNodes->item(0)->nodeValue;
                    if (!empty($desiredNameIdFormat)) {
                        foreach ($nameIdFormatNodes as $nameIdFormatNode) {
                            if ($nameIdFormatNode->nodeValue === $desiredNameIdFormat) {
                                $metadataInfo['sp']['NameIDFormat'] = $nameIdFormatNode->nodeValue;
                                break;
                            }
                        }
                    }
                }
            }
        } catch (Exception $e) {
            throw new Exception('Error parsing metadata. ' . $e->getMessage());
        }

        return $metadataInfo;
    }
}
