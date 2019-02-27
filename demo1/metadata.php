<?php

/**
 *  SAML Metadata view
 */

require_once __DIR__ . "/../vendor/autoload.php";

use Saml2\Error;
use Saml2\Settings;

$settingsInfo = require 'settings.php';

try {
    // $auth = new Saml2\Auth($settingsInfo);
    // $settings = $auth->getSettings();
    // Now we only validate SP settings
    $settings = new Settings($settingsInfo, true);
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
