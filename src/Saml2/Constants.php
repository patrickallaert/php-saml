<?php
namespace OneLogin\Saml2;

/**
 * @suppress PhanUnreferencedPublicClassConstant
 */
class Constants
{
    // NameID Formats
    public const NAMEID_EMAIL_ADDRESS = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';
    public const NAMEID_X509_SUBJECT_NAME = 'urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName';
    public const NAMEID_WINDOWS_DOMAIN_QUALIFIED_NAME = 'urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName';
    public const NAMEID_UNSPECIFIED = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';
    public const NAMEID_KERBEROS   = 'urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos';
    public const NAMEID_ENTITY     = 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity';
    public const NAMEID_TRANSIENT  = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient';
    public const NAMEID_PERSISTENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';
    public const NAMEID_ENCRYPTED = 'urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted';

    // Attribute Name Formats
    public const ATTRNAME_FORMAT_UNSPECIFIED = 'urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified';
    public const ATTRNAME_FORMAT_URI = 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri';
    public const ATTRNAME_FORMAT_BASIC = 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic';

    // Namespaces
    public const NS_SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';
    public const NS_SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol';
    public const NS_MD = 'urn:oasis:names:tc:SAML:2.0:metadata';
    public const NS_XS = 'http://www.w3.org/2001/XMLSchema';
    public const NS_XSI = 'http://www.w3.org/2001/XMLSchema-instance';
    public const NS_XENC = 'http://www.w3.org/2001/04/xmlenc#';
    public const NS_DS = 'http://www.w3.org/2000/09/xmldsig#';

    // Bindings
    public const BINDING_HTTP_POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';
    public const BINDING_HTTP_REDIRECT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';
    public const BINDING_HTTP_ARTIFACT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact';
    public const BINDING_SOAP = 'urn:oasis:names:tc:SAML:2.0:bindings:SOAP';
    public const BINDING_DEFLATE = 'urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE';

    // Subject Confirmation
    public const CM_BEARER = 'urn:oasis:names:tc:SAML:2.0:cm:bearer';
    public const CM_HOLDER_KEY = 'urn:oasis:names:tc:SAML:2.0:cm:holder-of-key';
    public const CM_SENDER_VOUCHES = 'urn:oasis:names:tc:SAML:2.0:cm:sender-vouches';

    // Status Codes
    public const STATUS_SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success';
    public const STATUS_REQUESTER = 'urn:oasis:names:tc:SAML:2.0:status:Requester';
    public const STATUS_RESPONDER = 'urn:oasis:names:tc:SAML:2.0:status:Responder';
    public const STATUS_VERSION_MISMATCH = 'urn:oasis:names:tc:SAML:2.0:status:VersionMismatch';
    public const STATUS_NO_PASSIVE = 'urn:oasis:names:tc:SAML:2.0:status:NoPassive';
    public const STATUS_PARTIAL_LOGOUT = 'urn:oasis:names:tc:SAML:2.0:status:PartialLogout';
    public const STATUS_PROXY_COUNT_EXCEEDED = 'urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded';
}
