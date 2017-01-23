<?php

namespace Parroauth2\Client\Exception;

/**
 * Class InvalidClientException
 */
class InvalidClientException extends OAuthServerException
{
    const ERROR_TYPE = "invalid_client";

    /**
     *
     */
    public function __construct($code, $message, $hint = "")
    {
        parent::__construct(self::ERROR_TYPE, $code, $message, $hint);
    }
}