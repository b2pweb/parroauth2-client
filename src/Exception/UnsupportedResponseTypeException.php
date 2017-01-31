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
     * @param string $message
     * @param string|null $hint
     * @param \Exception|null $previous
     * @param int $code
     */
    public function __construct($message, $hint = null, \Exception $previous = null, $code = 0)
    {
        parent::__construct(400, self::ERROR_TYPE, $message, $hint, $previous, $code);
    }
}