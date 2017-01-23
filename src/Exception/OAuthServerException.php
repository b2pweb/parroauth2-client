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
    protected $errorType;

    /**
     * @var string
     */
    protected $hint;


    /**
     * OAuthServerException constructor.
     *
     * @param string $errorType
     * @param int $code
     * @param string $message
     * @param string $hint
     */
    public function __construct($errorType, $code, $message, $hint = "")
    {
        parent::__construct($message, $code);

        $this->errorType = $errorType;
        $this->hint = $hint;
    }

    /**
     * @return string
     */
    public function errorType()
    {
        return $this->errorType;
    }

    /**
     * @return string
     */
    public function hint()
    {
        return $this->hint;
    }

    /**
     * Create the exception from a standard OAuth2 error response
     *
     * @param object $response The error response body. Should contains "error" and "error_description" attributes. May contains "hint" attribute
     * @param int $statusCode
     *
     * @return OAuthServerException
     */
    public static function createFromResponse($response, $statusCode)
    {
        switch ($response->error) {
            case AccessDeniedException::ERROR_TYPE:
                return new AccessDeniedException($statusCode, isset($response->error_description) ? $response->error_description : 'Access denied', isset($response->hint) ? $response->hint : "");

            case InvalidClientException::ERROR_TYPE:
                return new InvalidClientException($statusCode, isset($response->error_description) ? $response->error_description : 'Invalid client', isset($response->hint) ? $response->hint : "");

            case InvalidGrantException::ERROR_TYPE:
                return new InvalidGrantException($statusCode, isset($response->error_description) ? $response->error_description : 'Invalid grant', isset($response->hint) ? $response->hint : "");

            case InvalidRequestException::ERROR_TYPE:
                return new InvalidRequestException($statusCode, isset($response->error_description) ? $response->error_description : 'Invalid request', isset($response->hint) ? $response->hint : "");

            case InvalidScopeException::ERROR_TYPE:
                return new InvalidScopeException($statusCode, isset($response->error_description) ? $response->error_description : 'Invalid scope', isset($response->hint) ? $response->hint : "");

            case ServerErrorException::ERROR_TYPE:
                return new ServerErrorException($statusCode, isset($response->error_description) ? $response->error_description : 'Server error', isset($response->hint) ? $response->hint : "");

            case TemporarilyUnavailableException::ERROR_TYPE:
                return new TemporarilyUnavailableException($statusCode, isset($response->error_description) ? $response->error_description : 'Temporarily unavailable', isset($response->hint) ? $response->hint : "");

            case UnauthorizedClientException::ERROR_TYPE:
                return new UnauthorizedClientException($statusCode, isset($response->error_description) ? $response->error_description : 'Unauthorized client', isset($response->hint) ? $response->hint : "");

            case UnsupportedGrantTypeException::ERROR_TYPE:
                return new UnsupportedGrantTypeException($statusCode, isset($response->error_description) ? $response->error_description : 'Unsupported grant type', isset($response->hint) ? $response->hint : "");

            case UnsupportedResponseTypeException::ERROR_TYPE:
                return new UnsupportedResponseTypeException($statusCode, isset($response->error_description) ? $response->error_description : 'Unsupported response type', isset($response->hint) ? $response->hint : "");

            default:
                return new static($response->error, $statusCode, isset($response->error_description) ? $response->error_description : 'An error has occurred', isset($response->hint) ? $response->hint : "");
        }
    }
}