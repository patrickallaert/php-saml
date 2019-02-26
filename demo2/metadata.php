<?php
/**
 * SAMPLE Code to demonstrate how to handle a SAML assertion response.
 *
 * Your IdP will usually want your metadata, you can use this code to generate it once,
 * or expose it on a URL so your IdP can check it periodically.
 */

require_once __DIR__ . "/../vendor/autoload.php";

use OneLogin\Saml2\Metadata;
use OneLogin\Saml2\Settings;

header('Content-Type: text/xml');

echo Metadata::builder(new Settings([]));
