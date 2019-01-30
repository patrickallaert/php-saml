<?php
namespace OneLogin\Saml2;

use Exception;

class Error extends Exception
{
    // Errors
    const SETTINGS_FILE_NOT_FOUND = 0;
    const SETTINGS_INVALID_SYNTAX = 1;
    const SETTINGS_INVALID = 2;
    const METADATA_SP_INVALID = 3;
    const CERT_NOT_FOUND = 4;
    const REDIRECT_INVALID_URL = 5;
    const PUBLIC_CERT_FILE_NOT_FOUND = 6;
    const PRIVATE_KEY_FILE_NOT_FOUND = 7;
    const SAML_RESPONSE_NOT_FOUND = 8;
    const SAML_LOGOUTMESSAGE_NOT_FOUND = 9;
    const SAML_LOGOUTREQUEST_INVALID = 10;
    const SAML_LOGOUTRESPONSE_INVALID  = 11;
    const SAML_SINGLE_LOGOUT_NOT_SUPPORTED = 12;
    const PRIVATE_KEY_NOT_FOUND = 13;

    /**
     * @param string     $msg  Describes the error.
     * @param int        $code The code error (defined in the error class).
     * @param array|null $args Arguments used in the message that describes the error.
     */
    public function __construct(string $msg, int $code = 0, array $args = [])
    {
        if (!isset($args)) {
            $args = [];
        }
        parent::__construct(call_user_func_array('sprintf', array_merge([$msg], $args)), $code);
    }
}
