<?php

namespace Parroauth2\Client\Exception;

/**
 * Class InvalidScopeException
 */
class InvalidScopeException extends OAuthServerException
{
    const ERROR_TYPE = "invalid_scope";

    /**
     *
     */
    public function __construct($code, $message, $hint = "")
    {
        parent::__construct(self::ERROR_TYPE, $code, $message, $hint);
    }
}