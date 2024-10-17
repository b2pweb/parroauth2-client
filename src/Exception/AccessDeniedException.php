<?php

namespace Parroauth2\Client\Exception;

/**
 * Class AccessDeniedException
 */
class AccessDeniedException extends OAuthServerException
{
    public const ERROR_TYPE = 'access_denied';

    /**
     * AccessDeniedException constructor.
     *
     * @param string $message
     * @param string|null $hint
     * @param \Exception|null $previous
     * @param int $code
     */
    public function __construct($message, $hint = null, ?\Exception $previous = null, $code = 0)
    {
        parent::__construct(403, self::ERROR_TYPE, $message, $hint, $previous, $code);
    }
}
