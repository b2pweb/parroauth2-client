<?php

namespace Parroauth2\Client\Exception;

/**
 * Exception class for standard OAuth2 exceptions
 */
class OAuthServerException extends Parroauth2Exception
{
    /**
     * @var string
     */
    private $errorType;

    /**
     * @var string
     */
    private $hint;


    /**
     * OAuthServerException constructor.
     *
     * @param string $errorType
     * @param int $code
     * @param string $message
     * @param string $hint
     * @param \Exception $previous
     */
    public function __construct($errorType, $code, $message, $hint = null, \Exception $previous = null)
    {
        parent::__construct($message, $code, $previous);

        $this->errorType = $errorType;
        $this->hint = $hint;
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
     * @return string
     */
    public function getHint()
    {
        return $this->hint;
    }

    /**
     * Create the exception from a standard OAuth2 error response
     *
     * @param int $statusCode
     * @param string $type
     * @param string $message
     * @param string|null $hint
     * @param \Exception|null $previous
     *
     * @return OAuthServerException
     */
    public static function create($statusCode, $type, $message, $hint = null, \Exception $previous = null)
    {
        switch ($type) {
            case AccessDeniedException::ERROR_TYPE:
                return new AccessDeniedException($statusCode, $message ?: 'Access denied', $hint, $previous);

            case InvalidClientException::ERROR_TYPE:
                return new InvalidClientException($statusCode, $message ?: 'Invalid client', $hint, $previous);

            case InvalidGrantException::ERROR_TYPE:
                return new InvalidGrantException($statusCode, $message ?: 'Invalid grant', $hint, $previous);

            case InvalidRequestException::ERROR_TYPE:
                return new InvalidRequestException($statusCode, $message ?: 'Invalid request', $hint, $previous);

            case InvalidScopeException::ERROR_TYPE:
                return new InvalidScopeException($statusCode, $message ?: 'Invalid scope', $hint, $previous);

            case ServerErrorException::ERROR_TYPE:
                return new ServerErrorException($statusCode, $message ?: 'Server error', $hint, $previous);

            case TemporarilyUnavailableException::ERROR_TYPE:
                return new TemporarilyUnavailableException($statusCode, $message ?: 'Temporarily unavailable', $hint, $previous);

            case UnauthorizedClientException::ERROR_TYPE:
                return new UnauthorizedClientException($statusCode, $message ?: 'Unauthorized client', $hint, $previous);

            case UnsupportedGrantTypeException::ERROR_TYPE:
                return new UnsupportedGrantTypeException($statusCode, $message ?: 'Unsupported grant type', $hint, $previous);

            case UnsupportedResponseTypeException::ERROR_TYPE:
                return new UnsupportedResponseTypeException($statusCode, $message ?: 'Unsupported response type', $hint, $previous);

            default:
                return new static($type, $statusCode, $message ?: 'An error has occurred', $hint, $previous);
        }
    }
}