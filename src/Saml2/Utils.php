<?php
namespace Saml2;

use DateInterval;
use DateTime;
use DateTimeZone;
use DOMDocument;
use DOMElement;
use DOMNode;
use DOMNodeList;
use DOMXPath;
use Exception;
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use RuntimeException;

class Utils
{
    /**
     * @var bool Control if the `Forwarded-For-*` headers are used
     */
    private static $proxyVars = false;

    /**
     * @var string|null
     */
    private static $host;

    /**
     * @var string|null
     */
    private static $protocol;

    /**
     * @var int|null
     */
    private static $port;

    /**
     * @var string|null
     */
    private static $baseurlpath;

    /**
     * This function load an XML string in a save way.
     * Prevent XEE/XXE Attacks
     *
     * @throws Exception
     */
    public static function loadXML(DOMDocument $dom, string $xml): void
    {
        if ($xml === "") {
            throw new Exception('Empty string supplied as input');
        }

        $oldEntityLoader = libxml_disable_entity_loader();

        $res = $dom->loadXML($xml);

        libxml_disable_entity_loader($oldEntityLoader);

        foreach ($dom->childNodes as $child) {
            if ($child->nodeType === XML_DOCUMENT_TYPE_NODE) {
                throw new Exception(
                    'Detected use of DOCTYPE/ENTITY in XML, disabled to prevent XXE/XEE attacks'
                );
            }
        }

        if (!$res) {
            throw new Exception('An error occurred while loading the XML data');
        }
    }

    /**
     * This function attempts to validate an XML string against the specified schema.
     *
     * It will parse the string into a DOMDocument and validate this document against the schema.
     *
     * @throws Exception
     */
    public static function validateXML(DOMDocument $xml, string $schema): bool
    {
        libxml_clear_errors();
        libxml_use_internal_errors(true);

        $oldEntityLoader = libxml_disable_entity_loader(false);
        $res = $xml->schemaValidate(__DIR__ . '/schemas/' . $schema);
        libxml_disable_entity_loader($oldEntityLoader);

        return $res;
    }

    /**
     * Import a node tree into a target document
     * Copy it before a reference node as a sibling
     * and at the end of the copy remove
     * the reference node in the target document
     * As it were 'replacing' it
     * Leaving nested default namespaces alone
     * (Standard importNode with deep copy
     *  mangles nested default namespaces)
     *
     * The reference node must not be a DomDocument
     * It CAN be the top element of a document
     * Returns the copied node in the target document
     *
     * @throws Exception
     */
    public static function treeCopyReplace(DOMNode $targetNode, DOMNode $sourceNode, bool $recurse = false): DOMNode
    {
        if ($targetNode->parentNode === null) {
            throw new Exception('Illegal argument targetNode. It has no parentNode.');
        }
        $clonedNode = $targetNode->ownerDocument->importNode($sourceNode, false);
        $resultNode = $recurse ? $targetNode->appendChild($clonedNode) : $targetNode->parentNode->insertBefore($clonedNode, $targetNode);
        if ($sourceNode->childNodes !== null) {
            foreach ($sourceNode->childNodes as $child) {
                self::treeCopyReplace($resultNode, $child, true);
            }
        }
        if (!$recurse) {
            $targetNode->parentNode->removeChild($targetNode);
        }
        return $resultNode;
    }

    public static function formatCert(string $cert, bool $includeMarkers = true): string
    {
        $x509cert = str_replace(["\x0D", "\r", "\n"], "", $cert);
        if (!empty($x509cert)) {
            $x509cert = str_replace(['-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----', ' '], "", $x509cert);

            if ($includeMarkers) {
                return "-----BEGIN CERTIFICATE-----\n" . chunk_split($x509cert, 64, "\n") . "-----END CERTIFICATE-----\n";
            }
        }
        return $x509cert;
    }

    public static function formatPrivateKey(string $key, bool $includeMarkers = true): string
    {
        $key = str_replace(["\x0D", "\r", "\n"], "", $key);
        if ($key === "") {
            return $key;
        }

        if (strpos($key, '-----BEGIN PRIVATE KEY-----') !== false) {
            $key = str_replace(' ', '', self::getStringBetween($key, '-----BEGIN PRIVATE KEY-----', '-----END PRIVATE KEY-----'));

            if ($includeMarkers) {
                $key = "-----BEGIN PRIVATE KEY-----\n" . chunk_split($key, 64, "\n") . "-----END PRIVATE KEY-----\n";
            }
        } elseif (strpos($key, '-----BEGIN RSA PRIVATE KEY-----') !== false) {
            $key = str_replace(' ', '', self::getStringBetween($key, '-----BEGIN RSA PRIVATE KEY-----', '-----END RSA PRIVATE KEY-----'));

            if ($includeMarkers) {
                $key = "-----BEGIN RSA PRIVATE KEY-----\n" . chunk_split($key, 64, "\n") . "-----END RSA PRIVATE KEY-----\n";
            }
        } else {
            $key = str_replace(' ', '', $key);

            if ($includeMarkers) {
                $key = "-----BEGIN RSA PRIVATE KEY-----\n" . chunk_split($key, 64, "\n") . "-----END RSA PRIVATE KEY-----\n";
            }
        }
        return $key;
    }

    private static function getStringBetween(string $str, string $start, string $end): string
    {
        $str = ' ' . $str;
        $ini = strpos($str, $start);

        if ($ini === 0) {
            return '';
        }

        $ini += strlen($start);
        return substr($str, $ini, strpos($str, $end, $ini) - $ini);
    }

    /**
     * Executes a redirection to the provided url (or return the target url).
     *
     * @param string $url        The target url
     * @param array  $parameters Extra parameters to be passed as part of the url
     * @param bool   $stay       True if we want to stay (returns the url string) False to redirect
     *
     * @throws Error
     */
    public static function redirect(string $url, array $parameters = [], bool $stay = false): string
    {
        if ($url[0] === '/') {
            $url = self::getSelfURLhost() . $url;
        }

        /**
         * Verify that the URL matches the regex for the protocol.
         * By default this will check for http and https
         */
        $url = filter_var($url, FILTER_VALIDATE_URL);
        if ((!preg_match('@^https?://@i', $url)) || empty($url)) {
            throw new Error(
                'Redirect to invalid URL: ' . $url,
                Error::REDIRECT_INVALID_URL
            );
        }

        /* Add encoded parameters */
        $paramPrefix = strpos($url, '?') === false ? '?' : '&';

        foreach ($parameters as $name => $value) {
            if ($value === null) {
                $param = urlencode($name);
            } elseif (is_array($value)) {
                $param = "";
                foreach ($value as $val) {
                    $param .= urlencode($name) . "[]=" . urlencode($val) . '&';
                }
                if (!empty($param)) {
                    $param = substr($param, 0, -1);
                }
            } else {
                $param = urlencode($name) . '=' . urlencode($value);
            }

            if (!empty($param)) {
                $url .= $paramPrefix . $param;
                $paramPrefix = '&';
            }
        }

        if ($stay) {
            return $url;
        }

        header('Pragma: no-cache');
        header('Cache-Control: no-cache, must-revalidate');
        header('Location: ' . $url);
        exit;
    }

    /**
     * Set the Base URL value.
     *
     * @param string $baseurl The base url to be used when constructing URLs
     */
    public static function setBaseURL($baseurl): void
    {
        if (empty($baseurl)) {
            self::$host = null;
            self::$protocol = null;
            self::$port = null;
            self::$baseurlpath = null;
            return;
        }

        $baseurlpath = '/';
        $matches = [];

        if (!preg_match('#^https?://([^/]*)/?(.*)#i', $baseurl, $matches)) {
            return;
        }

        if (strpos($baseurl, 'https://') === false) {
            self::setSelfProtocol('http');
            $port = 80;
        } else {
            self::setSelfProtocol('https');
            $port = 443;
        }

        $currentHost = $matches[1];
        if (strpos($currentHost, ':') !== false) {
            [$currentHost, $possiblePort] = explode(':', $matches[1], 2);
            if (is_numeric($possiblePort)) {
                $port = (int) $possiblePort;
            }
        }

        if (isset($matches[2]) && !empty($matches[2])) {
            $baseurlpath = $matches[2];
        }

        self::setSelfHost($currentHost);
        self::setSelfPort($port);
        self::setBaseURLPath($baseurlpath);
    }

    /**
     * @param bool $proxyVars Whether to use `X-Forwarded-*` headers to determine port/domain/protocol
     */
    public static function setProxyVars(bool $proxyVars): void
    {
        self::$proxyVars = $proxyVars;
    }

    public static function getProxyVars(): bool
    {
        return self::$proxyVars;
    }

    /**
     * Returns the protocol + the current host + the port (if different than
     * common ports).
     */
    public static function getSelfURLhost(): string
    {
        $port = '';
        $portnumber = self::getSelfPort();

        if ($portnumber !== null && ($portnumber !== 80) && ($portnumber !== 443)) {
            $port = ':' . $portnumber;
        }

        return (self::isHTTPS() ? 'https' : 'http') . "://" . self::getSelfHost() . $port;
    }

    /**
     * @param string $host The host to use when constructing URLs
     */
    public static function setSelfHost($host): void
    {
        self::$host = $host;
    }

    /**
     * @param string $baseurlpath The baseurl path to use when constructing URLs
     */
    public static function setBaseURLPath($baseurlpath): void
    {
        if (empty($baseurlpath)) {
            self::$baseurlpath = null;
        } elseif ($baseurlpath === '/') {
            self::$baseurlpath = '/';
        } else {
            self::$baseurlpath = '/' . trim($baseurlpath, '/') . '/';
        }
    }

    public static function getBaseURLPath(): ?string
    {
        return self::$baseurlpath;
    }

    private static function getRawHost(): string
    {
        if (self::$host) {
            return self::$host;
        }

        if (self::getProxyVars() && array_key_exists('HTTP_X_FORWARDED_HOST', $_SERVER)) {
            return $_SERVER['HTTP_X_FORWARDED_HOST'];
        }

        if (array_key_exists('HTTP_HOST', $_SERVER)) {
            return $_SERVER['HTTP_HOST'];
        }

        if (array_key_exists('SERVER_NAME', $_SERVER)) {
            return $_SERVER['SERVER_NAME'];
        }

        return gethostname();
    }

    public static function setSelfPort(int $port): void
    {
        self::$port = $port;
    }

    public static function setSelfProtocol($protocol): void
    {
        self::$protocol = $protocol;
    }

    /**
     * Returns the current host.
     *
     * @return string $currentHost The current host
     */
    public static function getSelfHost(): string
    {
        $currentHost = self::getRawHost();

        // strip the port
        if (strpos($currentHost, ':') !== false) {
            [$currentHost] = explode(':', $currentHost, 2);
        }

        return $currentHost;
    }

    public static function getSelfPort(): ?int
    {
        if (self::$port) {
            return self::$port;
        }
        if (self::getProxyVars() && isset($_SERVER["HTTP_X_FORWARDED_PORT"])) {
            return (int) $_SERVER["HTTP_X_FORWARDED_PORT"];
        }
        if (isset($_SERVER["SERVER_PORT"])) {
            return (int) $_SERVER["SERVER_PORT"];
        }

        $currentHost = self::getRawHost();

        // strip the port
        if (strpos($currentHost, ':') !== false) {
            [, $port] = explode(':', $currentHost, 2);
            if (is_numeric($port)) {
                return (int) $port;
            }
        }
        return null;
    }

    public static function isHTTPS(): bool
    {
        if (self::$protocol) {
            return self::$protocol === "https";
        }

        if (self::getSelfPort() === 443) {
            return true;
        }

        if (self::getProxyVars() && isset($_SERVER['HTTP_X_FORWARDED_PROTO'])) {
            return $_SERVER['HTTP_X_FORWARDED_PROTO'] === "https";
        }

        return isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
    }

    /**
     * Returns the URL of the current host + current view.
     */
    public static function getSelfURLNoQuery(): string
    {
        $infoWithBaseURLPath = self::buildWithBaseURLPath($_SERVER['SCRIPT_NAME']);
        $selfURLNoQuery = self::getSelfURLhost() . (
            !empty($infoWithBaseURLPath) ? $infoWithBaseURLPath : $_SERVER['SCRIPT_NAME']
        );

        if (isset($_SERVER['PATH_INFO'])) {
            $selfURLNoQuery .= $_SERVER['PATH_INFO'];
        }

        return $selfURLNoQuery;
    }

    /**
     * Returns the routed URL of the current host + current view.
     */
    public static function getSelfRoutedURLNoQuery(): string
    {
        $route = '';

        if (!empty($_SERVER['REQUEST_URI'])) {
            $route = $_SERVER['REQUEST_URI'];
            if (!empty($_SERVER['QUERY_STRING'])) {
                $route = str_replace($_SERVER['QUERY_STRING'], '', $route);
                if (substr($route, -1) === '?') {
                    $route = substr($route, 0, -1);
                }
            }
        }

        $infoWithBaseURLPath = self::buildWithBaseURLPath($route);
        if (!empty($infoWithBaseURLPath)) {
            $route = $infoWithBaseURLPath;
        }

        return self::getSelfURLhost() . $route;
    }

    /**
     * Returns the URL of the current host + current view + query.
     */
    public static function getSelfURL(): string
    {
        $requestURI = '';
        if (!empty($_SERVER['REQUEST_URI'])) {
            $requestURI = $_SERVER['REQUEST_URI'];
            $matches = [];
            if ($requestURI[0] !== '/' && preg_match('#^https?://[^/]*(/.*)#i', $requestURI, $matches)) {
                $requestURI = $matches[1];
            }
        }

        $infoWithBaseURLPath = self::buildWithBaseURLPath($requestURI);
        if (!empty($infoWithBaseURLPath)) {
            $requestURI = $infoWithBaseURLPath;
        }

        return self::getSelfURLhost() . $requestURI;
    }

    /**
     * Returns the part of the URL with the BaseURLPath.
     *
     * @param string $info Contains path info
     */
    private static function buildWithBaseURLPath(string $info): string
    {
        $result = '';
        $baseURLPath = self::getBaseURLPath();
        if (!empty($baseURLPath)) {
            $result = $baseURLPath;
            if (!empty($info)) {
                $path = explode('/', $info);
                $extractedInfo = array_pop($path);
                if (!empty($extractedInfo)) {
                    $result .= $extractedInfo;
                }
            }
        }
        return $result;
    }

    /**
     * Extract a query param - as it was sent - from $_SERVER[QUERY_STRING]
     */
    private static function extractOriginalQueryParam(string $name): string
    {
        $substring = substr(
            $_SERVER['QUERY_STRING'],
            strpos($_SERVER['QUERY_STRING'], $name . '=') + strlen($name) + 1
        );
        return strpos($substring, '&') ? substr($substring, 0, strpos($substring, '&')) : $substring;
    }

    public static function generateUniqueID(): string
    {
        return 'ONELOGIN_' . sha1(uniqid((string) mt_rand(), true));
    }

    /**
     * Converts a UNIX timestamp to SAML2 timestamp on the form
     * yyyy-mm-ddThh:mm:ss(\.s+)?Z.
     */
    public static function parseTime2SAML(int $time): string
    {
        return (new DateTime("@$time", new DateTimeZone('UTC')))->format("Y-m-d\TH:i:s\Z");
    }

    /**
     * Converts a SAML2 timestamp on the form yyyy-mm-ddThh:mm:ss(\.s+)?Z
     * to a UNIX timestamp. The sub-second part is ignored.
     *
     * @param string $time The time we should convert (SAML Timestamp).
     *
     * @throws Exception
     */
    public static function parseSAML2Time($time): int
    {
        return (int) (new DateTime($time))->format("U");
    }

    /**
     * Compares 2 dates and returns the earliest.
     *
     * @throws Exception
     */
    public static function getExpireTime(?string $cacheDuration = null, ?int $validUntil = null): ?int
    {
        $expireTime = null;

        if ($cacheDuration !== null) {
            $now = new DateTime();
            $now->add(new DateInterval($cacheDuration));
            $expireTime = (int) $now->format("U");
        }

        if ($validUntil !== null && ($expireTime === null || $expireTime > $validUntil)) {
            return $validUntil;
        }

        return $expireTime;
    }


    /**
     * Extracts nodes from the DOMDocument.
     */
    public static function query(DOMDocument $dom, string $query, DOMNode $context = null): DOMNodeList
    {
        $xpath = new DOMXPath($dom);
        $xpath->registerNamespace('samlp', Constants::NS_SAMLP);
        $xpath->registerNamespace('saml', Constants::NS_SAML);
        $xpath->registerNamespace('ds', Constants::NS_DS);
        $xpath->registerNamespace('xenc', Constants::NS_XENC);
        $xpath->registerNamespace('xsi', Constants::NS_XSI);
        $xpath->registerNamespace('xs', Constants::NS_XS);
        $xpath->registerNamespace('md', Constants::NS_MD);

        return isset($context) ? $xpath->query($query, $context) : $xpath->query($query);
    }

    public static function deleteLocalSession(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_destroy();
        }

        unset($_SESSION);
    }

    public static function calculateX509Fingerprint(string $x509cert, string $alg = 'sha1'): ?string
    {
        $data = '';
        $inData = false;

        foreach (explode("\n", $x509cert) as $curData) {
            if (!$inData) {
                if (strncmp($curData, '-----BEGIN CERTIFICATE', 22) === 0) {
                    $inData = true;
                } elseif ((strncmp($curData, '-----BEGIN PUBLIC KEY', 21) === 0) || (strncmp($curData, '-----BEGIN RSA PRIVATE KEY', 26) === 0)) {
                    /* This isn't an X509 certificate. */
                    return null;
                }
            } else {
                if (strncmp($curData, '-----END CERTIFICATE', 20) === 0) {
                    break;
                }
                $data .= trim($curData);
            }
        }

        if (empty($data)) {
            return null;
        }

        $decodedData = base64_decode($data);

        switch ($alg) {
            case 'sha512':
            case 'sha384':
            case 'sha256':
                $fingerprint = hash($alg, $decodedData);
                break;
            case 'sha1':
            default:
                $fingerprint = strtolower(sha1($decodedData));
                break;
        }
        return $fingerprint;
    }

    public static function formatFingerPrint(string $fingerprint): string
    {
        return strtolower(str_replace(':', '', $fingerprint));
    }

    /**
     * @throws Exception
     */
    public static function generateNameId(
        string $fingerprint,
        ?string $spNameQualifier,
        ?string $spFormat = null,
        ?string $idpPublicCert = null,
        ?string $idpNameQualifier = null
    ): string {
        $doc = new DOMDocument();

        $nameId = $doc->createElement('saml:NameID');
        if ($spNameQualifier !== null) {
            $nameId->setAttribute('SPNameQualifier', $spNameQualifier);
        }
        if ($idpNameQualifier !== null) {
            $nameId->setAttribute('NameQualifier', $idpNameQualifier);
        }
        if ($spFormat !== null) {
            $nameId->setAttribute('Format', $spFormat);
        }
        $nameId->appendChild($doc->createTextNode($fingerprint));

        $doc->appendChild($nameId);

        if (!empty($idpPublicCert)) {
            $seckey = new XMLSecurityKey(XMLSecurityKey::RSA_1_5, ['type' => 'public']);
            $seckey->loadKey($idpPublicCert);

            $enc = new XMLSecEnc();
            $enc->setNode($nameId);
            $enc->type = XMLSecEnc::Element;

            $symmetricKey = new XMLSecurityKey(XMLSecurityKey::AES128_CBC);
            $symmetricKey->generateSessionKey();
            $enc->encryptKey($seckey, $symmetricKey);

            $newdoc = new DOMDocument();

            $encryptedID = $newdoc->createElement('saml:EncryptedID');

            $newdoc->appendChild($encryptedID);

            // @phan-suppress-next-line PhanTypeMismatchArgumentInternal
            $encryptedID->appendChild($encryptedID->ownerDocument->importNode($enc->encryptNode($symmetricKey), true));

            return $newdoc->saveXML($encryptedID);
        }

        return $doc->saveXML($nameId);
    }


    /**
     * Gets Status from a Response.
     *
     * @param DOMDocument $dom The Response as XML
     *
     * @return array $status The Status, an array with the code and a message.
     *
     * @throws ValidationError
     */
    public static function getStatus(DOMDocument $dom): array
    {
        $status = [];

        $statusEntry = self::query($dom, '/samlp:Response/samlp:Status');
        if ($statusEntry->length !== 1) {
            throw new ValidationError(
                "Missing Status on response",
                ValidationError::MISSING_STATUS
            );
        }

        $codeEntry = self::query($dom, '/samlp:Response/samlp:Status/samlp:StatusCode', $statusEntry->item(0));
        if ($codeEntry->length !== 1) {
            throw new ValidationError(
                "Missing Status Code on response",
                ValidationError::MISSING_STATUS_CODE
            );
        }
        $statusCode = $codeEntry->item(0);
        assert($statusCode instanceof DOMElement);
        $status['code'] = $statusCode->getAttribute('Value');

        $status['msg'] = '';
        $messageEntry = self::query($dom, '/samlp:Response/samlp:Status/samlp:StatusMessage', $statusEntry->item(0));
        if ($messageEntry->length === 0) {
            $subCodeEntry = self::query($dom, '/samlp:Response/samlp:Status/samlp:StatusCode/samlp:StatusCode', $statusEntry->item(0));
            if ($subCodeEntry->length === 1) {
                $subCode = $subCodeEntry->item(0);
                assert($subCode instanceof DOMElement);
                $status['msg'] = $subCode->getAttribute('Value');
            }
        } elseif ($messageEntry->length === 1) {
            $status['msg'] = $messageEntry->item(0)->textContent;
        }

        return $status;
    }

    /**
     * @throws ValidationError
     */
    public static function decryptElement(
        DOMElement $encryptedData,
        XMLSecurityKey $inputKey,
        bool $formatOutput = true
    ): DOMElement {
        $enc = new XMLSecEnc();

        $enc->setNode($encryptedData);
        $enc->type = $encryptedData->getAttribute("Type");

        $symmetricKey = $enc->locateKey($encryptedData);
        if (!$symmetricKey) {
            throw new ValidationError(
                'Could not locate key algorithm in encrypted data.',
                ValidationError::KEY_ALGORITHM_ERROR
            );
        }

        $symmetricKeyInfo = $enc->locateKeyInfo($symmetricKey);
        if (!$symmetricKeyInfo) {
            throw new ValidationError(
                "Could not locate <dsig:KeyInfo> for the encrypted key.",
                ValidationError::KEYINFO_NOT_FOUND_IN_ENCRYPTED_DATA
            );
        }

        $inputKeyAlgo = $inputKey->getAlgorithm();
        if ($symmetricKeyInfo->isEncrypted) {
            $symKeyInfoAlgo = $symmetricKeyInfo->getAlgorithm();

            if ($symKeyInfoAlgo === XMLSecurityKey::RSA_OAEP_MGF1P && $inputKeyAlgo === XMLSecurityKey::RSA_1_5) {
                $inputKeyAlgo = XMLSecurityKey::RSA_OAEP_MGF1P;
            }

            if ($inputKeyAlgo !== $symKeyInfoAlgo) {
                throw new ValidationError(
                    'Algorithm mismatch between input key and key used to encrypt ' .
                    ' the symmetric key for the message. Key was: ' .
                    var_export($inputKeyAlgo, true) . '; message was: ' .
                    var_export($symKeyInfoAlgo, true),
                    ValidationError::KEY_ALGORITHM_ERROR
                );
            }

            $encKey = $symmetricKeyInfo->encryptedCtx;

            if (!$encKey instanceof XMLSecEnc) {
                throw new RuntimeException("Incorrect type of encrypted context encountered.");
            }

            $symmetricKeyInfo->key = $inputKey->key;
            $keySize = $symmetricKey->getSymmetricKeySize();
            if ($keySize === null) {
                // To protect against "key oracle" attacks
                throw new ValidationError(
                    'Unknown key size for encryption algorithm: ' . var_export($symmetricKey->type, true),
                    ValidationError::KEY_ALGORITHM_ERROR
                );
            }

            $key = $encKey->decryptKey($symmetricKeyInfo);
            if (strlen($key) !== $keySize) {
                $key = sha1($encKey->getCipherValue() . sha1(serialize(openssl_pkey_get_details($symmetricKeyInfo->key)), true), true);

                /* Make sure that the key has the correct length. */
                if (strlen($key) > $keySize) {
                    $key = substr($key, 0, $keySize);
                } elseif (strlen($key) < $keySize) {
                    $key = str_pad($key, $keySize);
                }
            }
            $symmetricKey->loadKey($key);
        } else {
            $symKeyAlgo = $symmetricKey->getAlgorithm();
            if ($inputKeyAlgo !== $symKeyAlgo) {
                throw new ValidationError(
                    'Algorithm mismatch between input key and key in message. ' .
                    'Key was: ' . var_export($inputKeyAlgo, true) . '; message was: ' .
                    var_export($symKeyAlgo, true),
                    ValidationError::KEY_ALGORITHM_ERROR
                );
            }
            $symmetricKey = $inputKey;
        }

        $newDoc = new DOMDocument();
        if ($formatOutput) {
            $newDoc->preserveWhiteSpace = false;
            $newDoc->formatOutput = true;
        }
        try {
            self::loadXML(
                $newDoc,
                '<root xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">' . $enc->decryptNode(
                    $symmetricKey,
                    false
                ) . '</root>'
            );
        } catch (Exception $e) {
            throw new ValidationError(
                'Failed to parse decrypted XML.',
                ValidationError::INVALID_XML_FORMAT
            );
        }

        $decryptedElement = $newDoc->firstChild->firstChild;
        if ($decryptedElement === null) {
            throw new ValidationError(
                'Missing encrypted element.',
                ValidationError::MISSING_ENCRYPTED_ELEMENT
            );
        }

        return $decryptedElement;
    }

    private static function isSupportedSigningAlgorithm(string $algorithm): bool
    {
        switch ($algorithm) {
            case XMLSecurityKey::RSA_1_5:
            case XMLSecurityKey::RSA_SHA1:
            case XMLSecurityKey::RSA_SHA256:
            case XMLSecurityKey::RSA_SHA384:
            case XMLSecurityKey::RSA_SHA512:
                return true;
        }

        return false;
    }

    /**
     * Adds signature key and senders certificate to an element (Message or Assertion).
     *
     * @throws Exception
     */
    public static function addSign(
        string $xml,
        string $key,
        string $cert,
        string $signAlgorithm,
        string $digestAlgorithm
    ): string {
        self::loadXML($dom = new DOMDocument(), $xml);

        /* Load the private key. */
        $objKey = new XMLSecurityKey($signAlgorithm, ['type' => 'private']);
        $objKey->loadKey($key);

        /* Get the EntityDescriptor node we should sign. */
        $rootNode = $dom->firstChild;
        assert($rootNode instanceof DOMElement);

        /* Sign the metadata with our private key. */
        $objXMLSecDSig = new XMLSecurityDSig();
        $objXMLSecDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);

        $objXMLSecDSig->addReferenceList(
            [$rootNode],
            $digestAlgorithm,
            ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', XMLSecurityDSig::EXC_C14N],
            ['id_name' => 'ID']
        );

        $objXMLSecDSig->sign($objKey);

        /* Add the certificate to the signature. */
        $objXMLSecDSig->add509Cert($cert);

        $insertBefore = $rootNode->firstChild;
        if (in_array($rootNode->localName, ['AuthnRequest', 'Response', 'LogoutRequest', 'LogoutResponse'])) {
            $issuerNodes = self::query($dom, '/' . $rootNode->tagName . '/saml:Issuer');
            if ($issuerNodes->length === 1) {
                $insertBefore = $issuerNodes->item(0)->nextSibling;
            }
        }

        /* Add the signature. */
        $objXMLSecDSig->insertSignature($rootNode, $insertBefore);

        /* Return the DOM tree as a string. */
        return $dom->saveXML();
    }

    /**
     * Validates a signature (Message or Assertion).
     *
     * @param DOMDocument       $xml            The element we should validate
     * @param string|null       $cert           The public cert
     * @param string|null       $fingerprint    The fingerprint of the public cert
     * @param string            $fingerprintalg The algorithm used to get the fingerprint
     * @param string            $xpath          The xpath of the signed element
     * @param array|null        $multiCerts     Multiple public certs
     *
     * @throws Exception
     */
    public static function validateSign(
        DOMDocument $xml,
        ?string $cert,
        ?string $fingerprint,
        string $fingerprintalg,
        string $xpath,
        ?array $multiCerts
    ): bool {
        $objXMLSecDSig = new XMLSecurityDSig();
        $objXMLSecDSig->idKeys = ['ID'];

        $objXMLSecDSig->sigNode = self::query(clone $xml, $xpath)->item(0);

        if (!$objXMLSecDSig->sigNode) {
            throw new Exception('Cannot locate Signature Node');
        }

        $objKey = $objXMLSecDSig->locateKey();
        if (!$objKey) {
            throw new Exception('We have no idea about the key');
        }

        if (!self::isSupportedSigningAlgorithm($objKey->type)) {
            throw new Exception('Unsupported signing algorithm.');
        }

        $objXMLSecDSig->canonicalizeSignedInfo();

        try {
            $objXMLSecDSig->validateReference();
        } catch (Exception $e) {
            throw $e;
        }

        XMLSecEnc::staticLocateKeyInfo($objKey, $objXMLSecDSig->sigNode);

        if (!empty($multiCerts)) {
            // If multiple certs are provided, I may ignore $cert and
            // $fingerprint provided by the method and just check the
            // certs on the array
            $fingerprint = null;
        } else {
            // else I add the cert to the array in order to check
            // validate signatures with it and the with it and the
            // $fingerprint value
            $multiCerts = [$cert];
        }

        foreach ($multiCerts as $certificate) {
            if (!empty($certificate)) {
                $objKey->loadKey($certificate, false, true);
                if ($objXMLSecDSig->verify($objKey) === 1) {
                    return true;
                }
            } elseif (!empty($fingerprint)) {
                $domCert = $objKey->getX509Certificate();
                if (self::formatFingerPrint($fingerprint) === self::calculateX509Fingerprint($domCert, $fingerprintalg)) {
                    $objKey->loadKey($domCert, false, true);
                    if ($objXMLSecDSig->verify($objKey) === 1) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /**
     * @throws Exception
     */
    public static function validateBinarySign(
        string $messageType,
        array $getData,
        Settings $settings,
        bool $retrieveParametersFromServer
    ): bool {
        $signAlg = $getData['SigAlg'] ?? XMLSecurityKey::RSA_SHA1;

        if ($retrieveParametersFromServer) {
            $signedQuery = $messageType . '=' . self::extractOriginalQueryParam($messageType);
            if (isset($getData['RelayState'])) {
                $signedQuery .= '&RelayState=' . self::extractOriginalQueryParam('RelayState');
            }
            $signedQuery .= '&SigAlg=' . self::extractOriginalQueryParam('SigAlg');
        } else {
            $signedQuery = $messageType . '=' . urlencode($getData[$messageType]);
            if (isset($getData['RelayState'])) {
                $signedQuery .= '&RelayState=' . urlencode($getData['RelayState']);
            }
            $signedQuery .= '&SigAlg=' . urlencode($signAlg);
        }

        $strMessageType = $messageType === "SAMLRequest" ? "Logout Request" : "Logout Response";

        $multiX509SigningCertificates = $settings->getIdPMultipleX509SigningCertificate();
        $x509SigningCertificate = $settings->getIdPX509Certificate();
        $existsMultiX509Sign = !empty($multiX509SigningCertificates);
        if (empty($x509SigningCertificate) && !$existsMultiX509Sign) {
            throw new Error(
                "In order to validate the sign on the " . $strMessageType . ", the x509cert of the IdP is required",
                Error::CERT_NOT_FOUND
            );
        }

        $multiCerts = $existsMultiX509Sign ? $multiX509SigningCertificates : [$x509SigningCertificate];

        foreach ($multiCerts as $cert) {
            $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, ['type' => 'public']);
            $objKey->loadKey($cert, false, true);

            if ($signAlg !== XMLSecurityKey::RSA_SHA1) {
                try {
                    // do nothing if algorithm is already the type of the key
                    if ($objKey->type !== $signAlg) {
                        if (!self::isSupportedSigningAlgorithm($signAlg)) {
                            throw new Exception('Unsupported signing algorithm.');
                        }

                        $keyInfo = openssl_pkey_get_details($objKey->key);
                        if ($keyInfo === false) {
                            throw new Exception('Unable to get key details from XMLSecurityKey.');
                        }
                        if (!isset($keyInfo['key'])) {
                            throw new Exception('Missing key in public key details.');
                        }
                        $objKey = new XMLSecurityKey($signAlg, ['type' => "public"]);
                        $objKey->loadKey($keyInfo['key']);
                    }
                } catch (Exception $e) {
                    if (count($multiCerts) === 1) {
                        throw new ValidationError(
                            "Invalid signAlg in the received " . $strMessageType,
                            ValidationError::INVALID_SIGNATURE
                        );
                    }
                }
            }

            if ($objKey->verifySignature($signedQuery, base64_decode($_GET['Signature'])) === 1) {
                return true;
            }
        }
        return false;
    }
}
