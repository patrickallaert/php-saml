<?php

use OneLogin\Saml2\Constants;

$spBaseUrl = 'https://<your_domain>'; //or http://<your_domain>

return [
    'sp' => [
        'entityId' => $spBaseUrl . '/demo1/metadata.php',
        'assertionConsumerService' => [
            'url' => $spBaseUrl . '/demo1/index.php?acs',
        ],
        'singleLogoutService' => [
            'url' => $spBaseUrl . '/demo1/index.php?sls',
        ],
        'NameIDFormat' => Constants::NAMEID_UNSPECIFIED,
    ],
    'idp' => [
        'entityId' => '',
        'singleSignOnService' => ['url' => ''],
        'singleLogoutService' => ['url' => ''],
        'x509cert' => '',
    ],
];
