<?php

namespace Parroauth2\Client\Exception;

/**
 * Class InvalidRequestException
 */
class InvalidRequestException extends OAuthServerException
{
    const ERROR_TYPE = "invalid_request";

    /**
     *
     */
    public function __construct($code, $message, $hint = "")
    {
        parent::__construct(self::ERROR_TYPE, $code, $message, $hint);
    }
}