<?php

namespace Parroauth2\Client\Exception;

/**
 * Class UnauthorizedClientException
 */
class UnauthorizedClientException extends OAuthServerException
{
    const ERROR_TYPE = 'unauthorized_client';

    /**
     * UnauthorizedClientException constructor.
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