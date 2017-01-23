<?php

namespace Parroauth2\Client\Exception;

/**
 * Class TemporarilyUnavailableException
 */
class TemporarilyUnavailableException extends OAuthServerException
{
    const ERROR_TYPE = "temporarily_unavailable";

    /**
     *
     */
    public function __construct($code, $message, $hint = "")
    {
        parent::__construct(self::ERROR_TYPE, $code, $message, $hint);
    }
}