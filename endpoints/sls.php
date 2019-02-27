<?php

/**
 *  SP Single Logout Service Endpoint
 */

session_start();

require_once __DIR__ . "/../vendor/autoload.php";

use Saml2\Auth;

$auth = new Auth([]);

$auth->processSLO();

$errors = $auth->getErrors();

if (empty($errors)) {
    echo 'Sucessfully logged out';
} else {
    echo implode(', ', $errors);
}
