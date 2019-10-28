<?php

namespace Parroauth2\Client\EndPoint\Authorization;

/**
 * Wrap the authorization response for a response_type=code
 *
 * @see https://tools.ietf.org/html/rfc6749#section-4.1.2
 */
class AuthorizationCodeResponse
{
    /**
     * @var array
     */
    private $parameters;

    /**
     * AuthorizationCodeResponse constructor.
     *
     * @param array $parameters
     */
    public function __construct(array $parameters)
    {
        $this->parameters = $parameters;
    }

    /**
     * Get the authorization code
     *
     * @return string
     */
    public function code(): string
    {
        return $this->parameters['code'];
    }

    /**
     * Get the state
     *
     * @return string
     */
    public function state(): string
    {
        return $this->parameters['state'] ?? '';
    }

    /**
     * Check if the response is an error response
     *
     * @return bool
     */
    public function isError(): bool
    {
        return isset($this->parameters['error']);
    }

    /**
     * Get the error code
     *
     * @return string
     */
    public function error(): string
    {
        return $this->parameters['error'];
    }

    /**
     * Get the human readable error message
     *
     * @return string|null
     */
    public function errorDescription(): ?string
    {
        return $this->parameters['error_description'] ?? null;
    }
}
