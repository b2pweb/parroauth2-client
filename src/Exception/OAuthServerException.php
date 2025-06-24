<?php

namespace Parroauth2\Client\Exception;

/**
 * Exception class for standard OAuth2 exceptions
 */
class OAuthServerException extends Parroauth2Exception
{
    /**
     * The http status code
     *
     * @var int
     */
    private $statusCode;

    /**
     * @var string
     */
    private $errorType;

    /**
     * @var string|null
     */
    private $hint;


    /**
     * OAuthServerException constructor.
     *
     * @param int $statusCode
     * @param string $errorType
     * @param string $message
     * @param string|null $hint
     * @param \Exception|null $previous
     * @param int $code
     */
    public function __construct($statusCode, $errorType, $message, $hint = null, ?\Exception $previous = null, $code = 0)
    {
        parent::__construct($message, $code, $previous);

        $this->statusCode = $statusCode;
        $this->errorType = $errorType;
        $this->hint = $hint;
    }

    /**
     * Get the http status code
     *
     * @return int
     */
    public function getStatusCode()
    {
        return $this->statusCode;
    }

    /**
     * Get the error type
     *
     * @return string
     */
    public function getErrorType()
    {
        return $this->errorType;
    }

    /**
     * Get the error hint
     *
     * @return string|null
     */
    public function getHint()
    {
        return $this->hint;
    }

    /**
     * Create the exception from a standard OAuth2 error response
     *
     * @param string $type
     * @param string|null $message
     * @param string|null $hint
     * @param \Exception|null $previous
     * @param int $code
     *
     * @return OAuthServerException
     */
    public static function create(string $type, ?string $message, ?string $hint = null, ?\Exception $previous = null, int $code = 0): self
    {
        return match ($type) {
            AccessDeniedException::ERROR_TYPE => new AccessDeniedException($message ?? 'Access denied', $hint, $previous, $code),
            InvalidClientException::ERROR_TYPE => new InvalidClientException($message ?? 'Invalid client', $hint, $previous, $code),
            InvalidGrantException::ERROR_TYPE => new InvalidGrantException($message ?? 'Invalid grant', $hint, $previous, $code),
            InvalidRequestException::ERROR_TYPE => new InvalidRequestException($message ?? 'Invalid request', $hint, $previous, $code),
            InvalidScopeException::ERROR_TYPE => new InvalidScopeException($message ?? 'Invalid scope', $hint, $previous, $code),
            ServerErrorException::ERROR_TYPE => new ServerErrorException($message ?? 'Server error', $hint, $previous, $code),
            TemporarilyUnavailableException::ERROR_TYPE => new TemporarilyUnavailableException(
                $message ?? 'Temporarily unavailable',
                $hint,
                $previous,
                $code
            ),
            UnauthorizedClientException::ERROR_TYPE => new UnauthorizedClientException($message ?? 'Unauthorized client', $hint, $previous, $code),
            UnsupportedGrantTypeException::ERROR_TYPE => new UnsupportedGrantTypeException($message ?? 'Unsupported grant type', $hint, $previous, $code),
            UnsupportedResponseTypeException::ERROR_TYPE => new UnsupportedResponseTypeException(
                $message ?? 'Unsupported response type',
                $hint,
                $previous,
                $code
            ),
            default => new self(400, $type, $message ?? 'An error has occurred', $hint, $previous, $code),
        };
    }
}
