<?php

namespace Parroauth2\Client\Exception;

/**
 * Class UnsupportedResponseTypeException
 */
class UnsupportedResponseTypeException extends OAuthServerException
{
    const ERROR_TYPE = "unsupported_response_type";

    /**
     *
     */
    public function __construct($code, $message, $hint = "")
    {
        parent::__construct(self::ERROR_TYPE, $code, $message, $hint);
    }
}