<?php

/**
 *  SP Metadata Endpoint
 */

require_once __DIR__ . "/../vendor/autoload.php";

use Saml2\Auth;
use Saml2\Error;

try {
    $auth = new Auth([]);
    $settings = $auth->getSettings();
    $metadata = $settings->getSPMetadata();
    $errors = $settings->validateMetadata($metadata);
    if (empty($errors)) {
        header('Content-Type: text/xml');
        echo $metadata;
    } else {
        throw new Error(
            'Invalid SP metadata: ' . implode(', ', $errors),
            Error::METADATA_SP_INVALID
        );
    }
} catch (Exception $e) {
    echo $e->getMessage();
}
