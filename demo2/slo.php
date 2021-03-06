<?php
/**
 * SAMPLE Code to demonstrate how to initiate a SAML Single Log Out request
 *
 * When the user visits this URL, the browser will be redirected to the SLO
 * IdP with an SLO request.
 */

session_start();

require_once __DIR__ . "/../vendor/autoload.php";

use Saml2\LogoutRequest;
use Saml2\Settings;
use Saml2\Utils;

$samlSettings = new Settings([]);

$sloUrl = $samlSettings->getIdPSingleLogoutServiceUrl();
if (empty($sloUrl)) {
    throw new Exception("The IdP does not support Single Log Out");
}

if (isset($_SESSION['IdPSessionIndex']) && !empty($_SESSION['IdPSessionIndex'])) {
    $logoutRequest = new LogoutRequest($samlSettings, null, $_SESSION['IdPSessionIndex']);
} else {
    $logoutRequest = new LogoutRequest($samlSettings);
}

header("Location: " . Utils::redirect($sloUrl, ['SAMLRequest' => $logoutRequest->getRequest()], true));
