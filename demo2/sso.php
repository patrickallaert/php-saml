<?php
/**
 * SAMPLE Code to demonstrate how to initiate a SAML Authorization request
 *
 * When the user visits this URL, the browser will be redirected to the SSO
 * IdP with an authorization request. If successful, it will then be
 * redirected to the consume URL (specified in settings) with the auth
 * details.
 */

session_start();

require_once __DIR__ . "/../vendor/autoload.php";

use Saml2\Utils;

if (!isset($_SESSION['samlUserdata'])) {
    (new Saml2\Auth([]))->login();
} else {
    Utils::redirect(str_replace('/sso.php', '/index.php', Utils::getSelfURLNoQuery()));
}
