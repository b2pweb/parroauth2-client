<?php

namespace Parroauth2\Client\Exception;

/**
 * Class UnsupportedGrantTypeException
 */
class UnsupportedGrantTypeException extends OAuthServerException
{
    public const ERROR_TYPE = 'unsupported_grant_type';

    /**
     * UnsupportedGrantTypeException constructor.
     *
     * @param string $message
     * @param string|null $hint
     * @param \Exception|null $previous
     * @param int $code
     */
    public function __construct($message, $hint = null, ?\Exception $previous = null, $code = 0)
    {
        parent::__construct(400, self::ERROR_TYPE, $message, $hint, $previous, $code);
    }
}
