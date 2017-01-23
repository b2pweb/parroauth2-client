<?php

namespace Parroauth2\Client\Exception;

/**
 * Class AccessDeniedException
 */
class AccessDeniedException extends OAuthServerException
{
    const ERROR_TYPE = "access_denied";

    /**
     *
     */
    public function __construct($code, $message, $hint = "")
    {
        parent::__construct(self::ERROR_TYPE, $code, $message, $hint);
    }
}
