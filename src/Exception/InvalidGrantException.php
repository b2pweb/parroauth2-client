<?php

namespace Parroauth2\Client\Exception;

/**
 * Class InvalidGrantException
 */
class InvalidGrantException extends OAuthServerException
{
    const ERROR_TYPE = "invalid_grant";

    /**
     *
     */
    public function __construct($code, $message, $hint = "")
    {
        parent::__construct(self::ERROR_TYPE, $code, $message, $hint);
    }
}