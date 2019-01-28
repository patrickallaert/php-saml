<?php

    $spBaseUrl = 'https://<your_domain>'; //or http://<your_domain>

    $settingsInfo = [
        'sp' => [
            'entityId' => $spBaseUrl . '/demo1/metadata.php',
            'assertionConsumerService' => [
                'url' => $spBaseUrl . '/demo1/index.php?acs',
            ],
            'singleLogoutService' => [
                'url' => $spBaseUrl . '/demo1/index.php?sls',
            ],
            'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
        ],
        'idp' => [
            'entityId' => '',
            'singleSignOnService' => ['url' => ''],
            'singleLogoutService' => ['url' => ''],
            'x509cert' => '',
        ],
    ];
