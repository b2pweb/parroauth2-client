<?php

namespace Parroauth2\Client\Exception;

/**
 * Class UnsupportedGrantTypeException
 */
class UnsupportedGrantTypeException extends OAuthServerException
{
    const ERROR_TYPE = "unsupported_grant_type";

    /**
     *
     */
    public function __construct($code, $message, $hint = "")
    {
        parent::__construct(self::ERROR_TYPE, $code, $message, $hint);
    }
}