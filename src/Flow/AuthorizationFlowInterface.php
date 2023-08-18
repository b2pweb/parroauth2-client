<?php

namespace Parroauth2\Client\Flow;

use Parroauth2\Client\EndPoint\Authorization\AuthorizationEndPoint;
use Parroauth2\Client\EndPoint\Token\TokenResponse;
use Parroauth2\Client\Exception\Parroauth2Exception;

/**
 * Authentication flow using authorization endpoint
 *
 * @see AuthorizationEndPoint
 */
interface AuthorizationFlowInterface
{
    /**
     * Generates the authorization URI
     *
     * @param string|null $redirectUri The target URI, where
     *     AuthorizationFlowInterface::handleAuthorizationResponse() is called
     * @param array{id_token_hint?: string, login_hint?: string, display?: string, prompt?: string, max_age?: int} $parameters Additional parameters to pass to the authorization endpoint
     *
     * @return string
     */
    public function authorizationUri(?string $redirectUri = null, array $parameters = []): string;

    /**
     * Handle the response of the authorization endpoint
     *
     * @param array<string, string|string[]|null> $queryParameters
     *
     * @return TokenResponse
     *
     * @throws Parroauth2Exception When provider respond with an error
     * @throws \BadMethodCallException If AuthorizationFlowInterface::authorizationUri() is not called before
     * @throws \InvalidArgumentException When the response is invalid
     */
    public function handleAuthorizationResponse(array $queryParameters): TokenResponse;
}
