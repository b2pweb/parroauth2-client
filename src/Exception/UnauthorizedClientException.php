<?php

namespace Parroauth2\Client\Exception;

/**
 * Class UnauthorizedClientException
 */
class UnauthorizedClientException extends OAuthServerException
{
    const ERROR_TYPE = "unauthorized_client";

    /**
     *
     */
    public function __construct($code, $message, $hint = "")
    {
        parent::__construct(self::ERROR_TYPE, $code, $message, $hint);
    }
}