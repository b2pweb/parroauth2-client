<?php

namespace Parroauth2\Client\Exception;

/**
 * Class UnsupportedResponseTypeException
 */
class UnsupportedResponseTypeException extends OAuthServerException
{
    const ERROR_TYPE = 'unsupported_response_type';

    /**
     * UnsupportedResponseTypeException constructor.
     *
     * @param string $code
     * @param int $message
     * @param null $hint
     * @param \Exception|null $previous
     */
    public function __construct($code, $message, $hint = null, \Exception $previous = null)
    {
        parent::__construct(self::ERROR_TYPE, $code, $message, $hint, $previous);
    }
}