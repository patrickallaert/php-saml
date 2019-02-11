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

use OneLogin\Saml2\AuthnRequest;
use OneLogin\Saml2\Settings;
use OneLogin\Saml2\Utils;

if (!isset($_SESSION['samlUserdata'])) {
    $settings = new Settings();
    $idpData = $settings->getIdPData();
    header(
        "Location: " . Utils::redirect(
            $idpData['singleSignOnService']['url'],
            [
                'SAMLRequest' => (new AuthnRequest($settings))->getRequest(),
                'RelayState' => Utils::getSelfURLNoQuery(),
            ],
            true
        )
    );
} else {
    if (!empty($_SESSION['samlUserdata'])) {
        echo 'You have the following attributes:<br>';
        echo '<table><thead><th>Name</th><th>Values</th></thead><tbody>';
        foreach ($_SESSION['samlUserdata'] as $attributeName => $attributeValues) {
            echo '<tr><td>' . htmlentities($attributeName) . '</td><td><ul>';
            foreach ($attributeValues as $attributeValue) {
                echo '<li>' . htmlentities($attributeValue) . '</li>';
            }
            echo '</ul></td></tr>';
        }
        echo '</tbody></table>';
        if (!empty($_SESSION['IdPSessionIndex'])) {
            echo '<p>The SessionIndex of the IdP is: ' . $_SESSION['IdPSessionIndex'] . '</p>';
        }
    } else {
        echo "<p>You don't have any attribute</p>";
    }
    echo '<p><a href="slo.php">Logout</a></p>';
}
