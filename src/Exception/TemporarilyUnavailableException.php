<?php

namespace Parroauth2\Client\Exception;

/**
 * Class TemporarilyUnavailableException
 */
class TemporarilyUnavailableException extends OAuthServerException
{
    const ERROR_TYPE = 'temporarily_unavailable';

    /**
     * TemporarilyUnavailableException constructor.
     *
     * @param string $message
     * @param string|null $hint
     * @param \Exception|null $previous
     * @param int $code
     */
    public function __construct($message, $hint = null, \Exception $previous = null, $code = 0)
    {
        parent::__construct(503, self::ERROR_TYPE, $message, $hint, $previous, $code);
    }
}