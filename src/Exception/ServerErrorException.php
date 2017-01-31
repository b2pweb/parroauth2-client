<?php

namespace Parroauth2\Client\Exception;

/**
 * Class ServerErrorException
 */
class ServerErrorException extends OAuthServerException
{
    const ERROR_TYPE = 'server_error';

    /**
     * ServerErrorException constructor.
     *
     * @param string $message
     * @param string|null $hint
     * @param \Exception|null $previous
     * @param int $code
     */
    public function __construct($message, $hint = null, \Exception $previous = null, $code = 0)
    {
        parent::__construct(500, self::ERROR_TYPE, $message, $hint, $previous, $code);
    }
}