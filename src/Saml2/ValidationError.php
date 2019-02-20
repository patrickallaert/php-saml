<?php
namespace OneLogin\Saml2;

use Exception;

/**
 * This class implements another custom Exception handler,
 * related to exceptions that happens during validation process.
 */
class ValidationError extends Exception
{
    public const UNSUPPORTED_SAML_VERSION = 0;
    public const MISSING_ID = 1;
    public const WRONG_NUMBER_OF_ASSERTIONS = 2;
    public const MISSING_STATUS = 3;
    public const MISSING_STATUS_CODE = 4;
    public const STATUS_CODE_IS_NOT_SUCCESS = 5;
    public const WRONG_SIGNED_ELEMENT = 6;
    public const ID_NOT_FOUND_IN_SIGNED_ELEMENT = 7;
    public const DUPLICATED_ID_IN_SIGNED_ELEMENTS = 8;
    public const INVALID_SIGNED_ELEMENT = 9;
    public const DUPLICATED_REFERENCE_IN_SIGNED_ELEMENTS = 10;
    public const UNEXPECTED_SIGNED_ELEMENTS = 11;
    public const WRONG_NUMBER_OF_SIGNATURES_IN_RESPONSE = 12;
    public const WRONG_NUMBER_OF_SIGNATURES_IN_ASSERTION = 13;
    public const INVALID_XML_FORMAT = 14;
    public const WRONG_INRESPONSETO = 15;
    public const NO_ENCRYPTED_ASSERTION = 16;
    public const NO_ENCRYPTED_NAMEID = 17;
    public const MISSING_CONDITIONS = 18;
    public const ASSERTION_TOO_EARLY = 19;
    public const ASSERTION_EXPIRED = 20;
    public const WRONG_NUMBER_OF_AUTHSTATEMENTS = 21;
    public const ENCRYPTED_ATTRIBUTES = 23;
    public const WRONG_DESTINATION = 24;
    public const EMPTY_DESTINATION = 25;
    public const WRONG_AUDIENCE = 26;
    public const ISSUER_MULTIPLE_IN_RESPONSE = 27;
    public const ISSUER_NOT_FOUND_IN_ASSERTION = 28;
    public const WRONG_ISSUER = 29;
    public const SESSION_EXPIRED = 30;
    public const WRONG_SUBJECTCONFIRMATION = 31;
    public const NO_SIGNED_MESSAGE = 32;
    public const NO_SIGNED_ASSERTION = 33;
    public const NO_SIGNATURE_FOUND = 34;
    public const KEYINFO_NOT_FOUND_IN_ENCRYPTED_DATA = 35;
    public const NO_NAMEID = 38;
    public const EMPTY_NAMEID = 39;
    public const SP_NAME_QUALIFIER_NAME_MISMATCH = 40;
    public const DUPLICATED_ATTRIBUTE_NAME_FOUND = 41;
    public const INVALID_SIGNATURE = 42;
    public const RESPONSE_EXPIRED = 44;
    public const UNEXPECTED_REFERENCE = 45;
    public const NOT_SUPPORTED = 46;
    public const KEY_ALGORITHM_ERROR = 47;
    public const MISSING_ENCRYPTED_ELEMENT = 48;

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
