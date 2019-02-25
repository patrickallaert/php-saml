<?php

/**
 *  SAML Handler
 */

session_start();

require_once __DIR__ . "/../vendor/autoload.php";

use OneLogin\Saml2\Auth;
use OneLogin\Saml2\Utils;

$auth = new Auth(require 'settings.php');

if (isset($_GET['sso'])) {
    $auth->login();

    // If AuthNRequest ID need to be saved in order to later validate it, do instead
    // $ssoBuiltUrl = $auth->login(null, array(), false, false, true);
    // $_SESSION['AuthNRequestID'] = $auth->getLastRequestID();
    // header('Pragma: no-cache');
    // header('Cache-Control: no-cache, must-revalidate');
    // header('Location: ' . $ssoBuiltUrl);
    // exit();
} elseif (isset($_GET['sso2'])) {
    $auth->login($spBaseUrl . '/demo1/attrs.php');
} elseif (isset($_GET['slo'])) {
    $auth->logout(
        null,
        [],
        $_SESSION['samlNameId'] ?? null,
        $_SESSION['samlSessionIndex'] ?? null,
        false,
        $_SESSION['samlNameIdFormat'] ?? null,
        $_SESSION['samlNameIdNameQualifier'] ?? null,
        $_SESSION['samlNameIdSPNameQualifier'] ?? null
    );

    // If LogoutRequest ID need to be saved in order to later validate it, do instead
    // $sloBuiltUrl = $auth->logout(null, [], $_SESSION['samlNameId'] ?? null, $_SESSION['samlSessionIndex'] ?? null, true);
    // $_SESSION['LogoutRequestID'] = $auth->getLastRequestID();
    // header('Pragma: no-cache');
    // header('Cache-Control: no-cache, must-revalidate');
    // header('Location: ' . $sloBuiltUrl);
    // exit();
} elseif (isset($_GET['acs'])) {
    $auth->processResponse($_SESSION['AuthNRequestID'] ?? null);

    $errors = $auth->getErrors();

    if (!empty($errors)) {
        echo '<p>' . implode(', ', $errors) . '</p>';
    }

    if (!$auth->isAuthenticated()) {
        echo '<p>Not authenticated</p>';
        exit;
    }

    $_SESSION['samlUserdata'] = $auth->getAttributes();
    $_SESSION['samlNameId'] = $auth->getNameId();
    $_SESSION['samlNameIdFormat'] = $auth->getNameIdFormat();
    $_SESSION['samlNameIdNameQualifier'] = $auth->getNameIdNameQualifier();
    $_SESSION['samlNameIdSPNameQualifier'] = $auth->getNameIdSPNameQualifier();
    $_SESSION['samlSessionIndex'] = $auth->getSessionIndex();

    unset($_SESSION['AuthNRequestID']);
    if (isset($_POST['RelayState']) && Utils::getSelfURL() !== $_POST['RelayState']) {
        $auth->redirectTo($_POST['RelayState']);
    }
} elseif (isset($_GET['sls'])) {
    $auth->processSLO(false, $_SESSION['LogoutRequestID'] ?? null);
    $errors = $auth->getErrors();
    if (empty($errors)) {
        echo '<p>Sucessfully logged out</p>';
    } else {
        echo '<p>' . implode(', ', $errors) . '</p>';
    }
}

if (isset($_SESSION['samlUserdata'])) {
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
    } else {
        echo "<p>You don't have any attribute</p>";
    }

    echo '<p><a href="?slo" >Logout</a></p>';
} else {
    echo '<p><a href="?sso" >Login</a></p>';
    echo '<p><a href="?sso2" >Login and access to attrs.php page</a></p>';
}
