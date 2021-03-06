<?php
/**
 * SAMPLE Code to demonstrate how to handle a SAML assertion response.
 *
 * The URL of this file will have been given during the SAML authorization.
 * After a successful authorization, the browser will be directed to this
 * link where it will send a certified response via $_POST.
 */

require_once __DIR__ . "/../vendor/autoload.php";

use Saml2\Response;
use Saml2\Settings;

try {
    if (isset($_POST['SAMLResponse'])) {
        $samlResponse = new Response(new Settings([]), $_POST['SAMLResponse']);
        if ($samlResponse->isValid()) {
            echo 'You are: ' . $samlResponse->getNameId() . '<br>';
            $attributes = $samlResponse->getAttributes();
            if (!empty($attributes)) {
                echo 'You have the following attributes:<br>';
                echo '<table><thead><th>Name</th><th>Values</th></thead><tbody>';
                foreach ($attributes as $attributeName => $attributeValues) {
                    echo '<tr><td>' . htmlentities($attributeName) . '</td><td><ul>';
                    foreach ($attributeValues as $attributeValue) {
                        echo '<li>' . htmlentities($attributeValue) . '</li>';
                    }
                    echo '</ul></td></tr>';
                }
                echo '</tbody></table>';
            }
        } else {
            echo 'Invalid SAML Response';
        }
    } else {
        echo 'No SAML Response found in POST.';
    }
} catch (Exception $e) {
    echo 'Invalid SAML Response: ' . $e->getMessage();
}
