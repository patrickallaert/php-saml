<?php
    $settingsInfo = [
        'strict' => false,
        'sp' => [
            'entityId' => 'http://stuff.com/endpoints/metadata.php',
            'assertionConsumerService' => ['url' => 'http://stuff.com/endpoints/endpoints/acs.php'],
            'singleLogoutService' => ['url' => 'http://stuff.com/endpoints/endpoints/sls.php'],
            'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
            'privateKey' => 'MIICXgIBAAKBgQDivbhR7P516x/S3BqKxupQe0LONoliupiBOesCO3SHbDrl3+q9IbfnfmE04rNuMcPsIxB161TdDpIesLCn7c8aPHISKOtPlAeTZSnb8QAu7aRjZq3+PbrP5uW3TcfCGPtKTytHOge/OlJbo078dVhXQ14d1EDwXJW1rRXuUt4C8QIDAQABAoGAD4/Z4LWVWV6D1qMIp1Gzr0ZmdWTE1SPdZ7Ej8glGnCzPdguCPuzbhGXmIg0VJ5D+02wsqws1zd48JSMXXM8zkYZVwQYIPUsNn5FetQpwxDIMPmhHg+QNBgwOnk8JK2sIjjLPL7qY7Itv7LT7Gvm5qSOkZ33RCgXcgz+okEIQMYkCQQDzbTOyDL0c5WQV6A2k06T/azdhUdGXF9C0+WkWSfNaovmTgRXh1G+jMlr82Snz4p4/STt7P/XtyWzF3pkVgZr3AkEA7nPjXwHlttNEMo6AtxHd47nizK2NUN803ElIUT8P9KSCoERmSXq66PDekGNic4ldpsSvOeYCk8MAYoDBy9kvVwJBAMLgX4xg6lzhv7hR5+pWjTb1rIY6rCHbrPfU264+UZXz9v2BT/VUznLF81WMvStD9xAPHpFS6R0OLghSZhdzhI0CQQDL8Duvfxzrn4b9QlmduV8wLERoT6rEVxKLsPVz316TGrxJvBZLk/cV0SRZE1cZf4ukXSWMfEcJ/0Zt+LdG1CqjAkEAqwLSglJ9Dy3HpgMz4vAAyZWzAxvyA1zW0no9GOLcPQnYaNUN/Fy2SYtETXTb0CQ9X1rt8ffkFP7ya+5TC83aMg==',
            'x509cert' => 'MIICgTCCAeoCCQCbOlrWDdX7FTANBgkqhkiG9w0BAQUFADCBhDELMAkGA1UEBhMCTk8xGDAWBgNVBAgTD0FuZHJlYXMgU29sYmVyZzEMMAoGA1UEBxMDRm9vMRAwDgYDVQQKEwdVTklORVRUMRgwFgYDVQQDEw9mZWlkZS5lcmxhbmcubm8xITAfBgkqhkiG9w0BCQEWEmFuZHJlYXNAdW5pbmV0dC5ubzAeFw0wNzA2MTUxMjAxMzVaFw0wNzA4MTQxMjAxMzVaMIGEMQswCQYDVQQGEwJOTzEYMBYGA1UECBMPQW5kcmVhcyBTb2xiZXJnMQwwCgYDVQQHEwNGb28xEDAOBgNVBAoTB1VOSU5FVFQxGDAWBgNVBAMTD2ZlaWRlLmVybGFuZy5ubzEhMB8GCSqGSIb3DQEJARYSYW5kcmVhc0B1bmluZXR0Lm5vMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDivbhR7P516x/S3BqKxupQe0LONoliupiBOesCO3SHbDrl3+q9IbfnfmE04rNuMcPsIxB161TdDpIesLCn7c8aPHISKOtPlAeTZSnb8QAu7aRjZq3+PbrP5uW3TcfCGPtKTytHOge/OlJbo078dVhXQ14d1EDwXJW1rRXuUt4C8QIDAQABMA0GCSqGSIb3DQEBBQUAA4GBACDVfp86HObqY+e8BUoWQ9+VMQx1ASDohBjwOsg2WykUqRXF+dLfcUH9dWR63CtZIKFDbStNomPnQz7nbK+onygwBspVEbnHuUihZq3ZUdmumQqCw4Uvs/1Uvq3orOo/WJVhTyvLgFVK2QarQ4/67OZfHd7R+POBXhophSMv1ZOo',
            'x509certNew' => 'MIICVDCCAb2gAwIBAgIBADANBgkqhkiG9w0BAQ0FADBHMQswCQYDVQQGEwJ1czEQMA4GA1UECAwHZXhhbXBsZTEQMA4GA1UECgwHZXhhbXBsZTEUMBIGA1UEAwwLZXhhbXBsZS5jb20wHhcNMTcwNDA3MDgzMDAzWhcNMjcwNDA1MDgzMDAzWjBHMQswCQYDVQQGEwJ1czEQMA4GA1UECAwHZXhhbXBsZTEQMA4GA1UECgwHZXhhbXBsZTEUMBIGA1UEAwwLZXhhbXBsZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKhPS4/0azxbQekHHewQGKD7Pivr3CDpsrKxY3xlVanxj427OwzOb5KUVzsDEazumt6sZFY8HfidsjXY4EYA4ZzyL7ciIAR5vlAsIYN9nJ4AwVDnN/RjVwj+TN6BqWPLpVIpHc6Dl005HyE0zJnk1DZDn2tQVrIzbD3FhCp7YeotAgMBAAGjUDBOMB0GA1UdDgQWBBRYZx4thASfNvR/E7NsCF2IaZ7wIDAfBgNVHSMEGDAWgBRYZx4thASfNvR/E7NsCF2IaZ7wIDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBDQUAA4GBACz4aobx9aG3kh+rNyrlgM3K6dYfnKG1/YH5sJCAOvg8kDr0fQAQifH8lFVWumKUMoAe0bFTfwWtp/VJ8MprrEJth6PFeZdczpuv+fpLcNj2VmNVJqvQYvS4m36OnBFh1QFZW8UrbFIfdtm2nuZ+twSKqfKwjLdqcoX0p39h7Uw/',
        ],
        'idp' => [
            'entityId' => 'http://idp.example.com/',
            'singleSignOnService' => ['url' => 'http://idp.example.com/SSOService.php'],
            'singleLogoutService' => ['url' => 'http://idp.example.com/SingleLogoutService.php'],
            'x509cert' => 'MIICgTCCAeoCCQCbOlrWDdX7FTANBgkqhkiG9w0BAQUFADCBhDELMAkGA1UEBhMCTk8xGDAWBgNVBAgTD0FuZHJlYXMgU29sYmVyZzEMMAoGA1UEBxMDRm9vMRAwDgYDVQQKEwdVTklORVRUMRgwFgYDVQQDEw9mZWlkZS5lcmxhbmcubm8xITAfBgkqhkiG9w0BCQEWEmFuZHJlYXNAdW5pbmV0dC5ubzAeFw0wNzA2MTUxMjAxMzVaFw0wNzA4MTQxMjAxMzVaMIGEMQswCQYDVQQGEwJOTzEYMBYGA1UECBMPQW5kcmVhcyBTb2xiZXJnMQwwCgYDVQQHEwNGb28xEDAOBgNVBAoTB1VOSU5FVFQxGDAWBgNVBAMTD2ZlaWRlLmVybGFuZy5ubzEhMB8GCSqGSIb3DQEJARYSYW5kcmVhc0B1bmluZXR0Lm5vMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDivbhR7P516x/S3BqKxupQe0LONoliupiBOesCO3SHbDrl3+q9IbfnfmE04rNuMcPsIxB161TdDpIesLCn7c8aPHISKOtPlAeTZSnb8QAu7aRjZq3+PbrP5uW3TcfCGPtKTytHOge/OlJbo078dVhXQ14d1EDwXJW1rRXuUt4C8QIDAQABMA0GCSqGSIb3DQEBBQUAA4GBACDVfp86HObqY+e8BUoWQ9+VMQx1ASDohBjwOsg2WykUqRXF+dLfcUH9dWR63CtZIKFDbStNomPnQz7nbK+onygwBspVEbnHuUihZq3ZUdmumQqCw4Uvs/1Uvq3orOo/WJVhTyvLgFVK2QarQ4/67OZfHd7R+POBXhophSMv1ZOo',
        ],
        'compress' => [
            'requests' => true,
            'responses' => true,
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
