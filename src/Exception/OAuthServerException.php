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
     * @var string
     */
    private $hint;


    /**
     * OAuthServerException constructor.
     *
     * @param int $statusCode
     * @param string $errorType
     * @param string $message
     * @param string $hint
     * @param \Exception $previous
     * @param int $code
     */
    public function __construct($statusCode, $errorType, $message, $hint = null, \Exception $previous = null, $code = 0)
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
     * @return string
     */
    public function getHint()
    {
        return $this->hint;
    }

    /**
     * Create the exception from a standard OAuth2 error response
     *
     * @param string $type
     * @param string $message
     * @param string|null $hint
     * @param \Exception|null $previous
     *
     * @return OAuthServerException
     */
    public static function create($type, $message, $hint = null, \Exception $previous = null, $code = 0)
    {
        switch ($type) {
            case AccessDeniedException::ERROR_TYPE:
                return new AccessDeniedException($message ?: 'Access denied', $hint, $previous, $code);

            case InvalidClientException::ERROR_TYPE:
                return new InvalidClientException($message ?: 'Invalid client', $hint, $previous, $code);

            case InvalidGrantException::ERROR_TYPE:
                return new InvalidGrantException($message ?: 'Invalid grant', $hint, $previous, $code);

            case InvalidRequestException::ERROR_TYPE:
                return new InvalidRequestException($message ?: 'Invalid request', $hint, $previous, $code);

            case InvalidScopeException::ERROR_TYPE:
                return new InvalidScopeException($message ?: 'Invalid scope', $hint, $previous, $code);

            case ServerErrorException::ERROR_TYPE:
                return new ServerErrorException($message ?: 'Server error', $hint, $previous, $code);

            case TemporarilyUnavailableException::ERROR_TYPE:
                return new TemporarilyUnavailableException($message ?: 'Temporarily unavailable', $hint, $previous, $code);

            case UnauthorizedClientException::ERROR_TYPE:
                return new UnauthorizedClientException($message ?: 'Unauthorized client', $hint, $previous, $code);

            case UnsupportedGrantTypeException::ERROR_TYPE:
                return new UnsupportedGrantTypeException($message ?: 'Unsupported grant type', $hint, $previous, $code);

            case UnsupportedResponseTypeException::ERROR_TYPE:
                return new UnsupportedResponseTypeException($message ?: 'Unsupported response type', $hint, $previous, $code);

            default:
                return new static(400, $type, $message ?: 'An error has occurred', $hint, $previous, $code);
        }
    }
}