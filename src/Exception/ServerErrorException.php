<?php

namespace Parroauth2\Client\Exception;

/**
 * Class ServerErrorException
 */
class ServerErrorException extends OAuthServerException
{
    const ERROR_TYPE = "server_error";

    /**
     *
     */
    public function __construct($code, $message, $hint = "")
    {
        parent::__construct(self::ERROR_TYPE, $code, $message, $hint);
    }
}