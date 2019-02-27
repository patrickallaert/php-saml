<?php

use Saml2\Constants;

return [
    'strict' => false,
    'sp' => [
        'entityId' => 'http://stuff.com/endpoints/metadata.php',
        'assertionConsumerService' => ['url' => 'http://stuff.com/endpoints/endpoints/acs.php'],
        'singleLogoutService' => ['url' => 'http://stuff.com/endpoints/endpoints/sls.php'],
        "NameIDFormat" => Constants::NAMEID_UNSPECIFIED,
        'attributeConsumingService' => [
            'serviceName' => 'Service Name',
            'serviceDescription' => 'Service Description',
            'requestedAttributes' => [
                [
                    'nameFormat' => Saml2\Constants::ATTRNAME_FORMAT_URI,
                    'isRequired' => true,
                    'name' => 'Email',
                    'friendlyName' => 'Email',
                ],
                [
                    'nameFormat' => Saml2\Constants::ATTRNAME_FORMAT_URI,
                    'isRequired' => true,
                    'name' => 'FirstName',
                ],
                [
                    'nameFormat' => Saml2\Constants::ATTRNAME_FORMAT_URI,
                    'isRequired' => true,
                    'name' => 'LastName',
                ],
            ],
        ],
    ],
    'idp' => [
        'entityId' => 'http://idp.example.com/',
        'singleSignOnService' => ['url' => 'http://idp.example.com/SSOService.php'],
        'singleLogoutService' => ['url' => 'http://idp.example.com/SingleLogoutService.php'],
        'x509cert' => 'MIICgTCCAeoCCQCbOlrWDdX7FTANBgkqhkiG9w0BAQUFADCBhDELMAkGA1UEBhMCTk8xGDAWBgNVBAgTD0FuZHJlYXMgU29sYmVyZzEMMAoGA1UEBxMDRm9vMRAwDgYDVQQKEwdVTklORVRUMRgwFgYDVQQDEw9mZWlkZS5lcmxhbmcubm8xITAfBgkqhkiG9w0BCQEWEmFuZHJlYXNAdW5pbmV0dC5ubzAeFw0wNzA2MTUxMjAxMzVaFw0wNzA4MTQxMjAxMzVaMIGEMQswCQYDVQQGEwJOTzEYMBYGA1UECBMPQW5kcmVhcyBTb2xiZXJnMQwwCgYDVQQHEwNGb28xEDAOBgNVBAoTB1VOSU5FVFQxGDAWBgNVBAMTD2ZlaWRlLmVybGFuZy5ubzEhMB8GCSqGSIb3DQEJARYSYW5kcmVhc0B1bmluZXR0Lm5vMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDivbhR7P516x/S3BqKxupQe0LONoliupiBOesCO3SHbDrl3+q9IbfnfmE04rNuMcPsIxB161TdDpIesLCn7c8aPHISKOtPlAeTZSnb8QAu7aRjZq3+PbrP5uW3TcfCGPtKTytHOge/OlJbo078dVhXQ14d1EDwXJW1rRXuUt4C8QIDAQABMA0GCSqGSIb3DQEBBQUAA4GBACDVfp86HObqY+e8BUoWQ9+VMQx1ASDohBjwOsg2WykUqRXF+dLfcUH9dWR63CtZIKFDbStNomPnQz7nbK+onygwBspVEbnHuUihZq3ZUdmumQqCw4Uvs/1Uvq3orOo/WJVhTyvLgFVK2QarQ4/67OZfHd7R+POBXhophSMv1ZOo',
    ],
    'security' => [
        'authnRequestsSigned' => false,
        'wantAssertionsSigned' => false,
        'signMetadata' => false,
    ],
    'contactPerson' => [
        'technical' => [
            'givenName' => 'technical_name',
            'emailAddress' => 'technical@example.com',
        ],
        'support' => [
            'givenName' => 'support_name',
            'emailAddress' => 'support@example.com',
        ],
    ],
    'organization' => [
        'en-US' => [
            'name' => 'sp_test',
            'displayname' => 'SP test',
            'url' => 'http://sp.example.com',
        ],
    ],
];
