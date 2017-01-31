<?php

namespace Parroauth2\Client\Exception;

/**
 * Class InvalidClientException
 */
class InvalidClientException extends OAuthServerException
{
    const ERROR_TYPE = 'invalid_client';

    /**
     * InvalidClientException constructor.
     *
     * @param string $message
     * @param string|null $hint
     * @param \Exception|null $previous
     * @param int $code
     */
    public function __construct($message, $hint = null, \Exception $previous = null, $code = 0)
    {
        parent::__construct(401, self::ERROR_TYPE, $message, $hint, $previous, $code);
    }
}