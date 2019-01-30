<?php
namespace OneLogin\Saml2;

use Exception;

/**
 * This class implements another custom Exception handler,
 * related to exceptions that happens during validation process.
 */
class ValidationError extends Exception
{
    // Validation Errors
    const UNSUPPORTED_SAML_VERSION = 0;
    const MISSING_ID = 1;
    const WRONG_NUMBER_OF_ASSERTIONS = 2;
    const MISSING_STATUS = 3;
    const MISSING_STATUS_CODE = 4;
    const STATUS_CODE_IS_NOT_SUCCESS = 5;
    const WRONG_SIGNED_ELEMENT = 6;
    const ID_NOT_FOUND_IN_SIGNED_ELEMENT = 7;
    const DUPLICATED_ID_IN_SIGNED_ELEMENTS = 8;
    const INVALID_SIGNED_ELEMENT = 9;
    const DUPLICATED_REFERENCE_IN_SIGNED_ELEMENTS = 10;
    const UNEXPECTED_SIGNED_ELEMENTS = 11;
    const WRONG_NUMBER_OF_SIGNATURES_IN_RESPONSE = 12;
    const WRONG_NUMBER_OF_SIGNATURES_IN_ASSERTION = 13;
    const INVALID_XML_FORMAT = 14;
    const WRONG_INRESPONSETO = 15;
    const NO_ENCRYPTED_ASSERTION = 16;
    const NO_ENCRYPTED_NAMEID = 17;
    const MISSING_CONDITIONS = 18;
    const ASSERTION_TOO_EARLY = 19;
    const ASSERTION_EXPIRED = 20;
    const WRONG_NUMBER_OF_AUTHSTATEMENTS = 21;
    const ENCRYPTED_ATTRIBUTES = 23;
    const WRONG_DESTINATION = 24;
    const EMPTY_DESTINATION = 25;
    const WRONG_AUDIENCE = 26;
    const ISSUER_MULTIPLE_IN_RESPONSE = 27;
    const ISSUER_NOT_FOUND_IN_ASSERTION = 28;
    const WRONG_ISSUER = 29;
    const SESSION_EXPIRED = 30;
    const WRONG_SUBJECTCONFIRMATION = 31;
    const NO_SIGNED_MESSAGE = 32;
    const NO_SIGNED_ASSERTION = 33;
    const NO_SIGNATURE_FOUND = 34;
    const KEYINFO_NOT_FOUND_IN_ENCRYPTED_DATA = 35;
    const NO_NAMEID = 38;
    const EMPTY_NAMEID = 39;
    const SP_NAME_QUALIFIER_NAME_MISMATCH = 40;
    const DUPLICATED_ATTRIBUTE_NAME_FOUND = 41;
    const INVALID_SIGNATURE = 42;
    const RESPONSE_EXPIRED = 44;
    const UNEXPECTED_REFERENCE = 45;
    const NOT_SUPPORTED = 46;
    const KEY_ALGORITHM_ERROR = 47;
    const MISSING_ENCRYPTED_ELEMENT = 48;

    /**
     * @param array|null $args Arguments used in the message that describes the error.
     */
    public function __construct(string $msg, int $code = 0, $args = [])
    {
        if (!isset($args)) {
            $args = [];
        }
        parent::__construct(call_user_func_array('sprintf', array_merge([$msg], $args)), $code);
    }
}
