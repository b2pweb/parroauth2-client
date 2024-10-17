<?php

namespace Parroauth2\Client\EndPoint\Token;

use Parroauth2\Client\Authentication\ClientAuthenticationMethodInterface;
use Parroauth2\Client\ClientInterface;
use Parroauth2\Client\EndPoint\CallableEndPointInterface;
use Parroauth2\Client\EndPoint\EndPointParametersTrait;
use Parroauth2\Client\EndPoint\EndPointResponseListenerTrait;
use Parroauth2\Client\EndPoint\EndPointTransformerInterface;

/**
 * Endpoint for generates an access token
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
 *
 * @implements CallableEndPointInterface<TokenResponse>
 */
class TokenEndPoint implements CallableEndPointInterface
{
    use EndPointParametersTrait;
    /** @use EndPointResponseListenerTrait<TokenResponse> */
    use EndPointResponseListenerTrait;

    public const NAME = 'token';

    public const GRANT_TYPE_CODE = 'authorization_code';
    public const GRANT_TYPE_PASSWORD = 'password';
    public const GRANT_TYPE_REFRESH = 'refresh_token';
    public const GRANT_TYPE_CLIENT_CREDENTIALS = 'client_credentials';

    /**
     * @var ClientInterface
     * @readonly
     */
    private $client;

    /**
     * @var callable(array):TokenResponse
     * @readonly
     */
    private $responseFactory;


    /**
     * TokenEndPoint constructor.
     *
     * @param ClientInterface $client
     * @param null|callable(array):TokenResponse $responseFactory
     */
    public function __construct(ClientInterface $client, ?callable $responseFactory = null)
    {
        $this->client = $client;
        $this->responseFactory = $responseFactory ?: function (array $response): TokenResponse {
            return new TokenResponse($response);
        };
    }

    /**
     * {@inheritdoc}
     *
     * @psalm-mutation-free
     */
    public function name(): string
    {
        return self::NAME;
    }

    /**
     * {@inheritdoc}
     */
    public function apply(EndPointTransformerInterface $transformer): TokenEndPoint
    {
        return $transformer->onToken($this);
    }

    /**
     * Configure a grant type authorization_code token request
     *
     * @param string $authorizationCode The received authorization code
     * @param string|null $redirectUri The redirect uri given to the authorization request
     *
     * @return static
     *
     * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
     */
    public function code(string $authorizationCode, ?string $redirectUri = null): TokenEndPoint
    {
        $endpoint = clone $this;

        $endpoint->parameters['grant_type'] = self::GRANT_TYPE_CODE;
        $endpoint->parameters['code'] = $authorizationCode;
        $endpoint->parameters['client_id'] = $this->client->clientId();

        if ($redirectUri) {
            $endpoint->parameters['redirect_uri'] = $redirectUri;
        }

        return $endpoint;
    }

    /**
     * Configure a grant type client credentials token request
     *
     * @param list<string>|null $scopes List of scopes to grant
     *
     * @return static
     *
     * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.4.2
     *
     * @psalm-mutation-free
     */
    public function clientCredentials(?array $scopes = null): TokenEndPoint
    {
        $endpoint = clone $this;

        $endpoint->parameters['grant_type'] = self::GRANT_TYPE_CLIENT_CREDENTIALS;

        if ($scopes) {
            $endpoint->parameters['scope'] = implode(' ', $scopes);
        }

        return $endpoint;
    }

    /**
     * Configure a grant type password token request
     *
     * @param string $username The resource owner username
     * @param string $password The resource owner password
     * @param list<string>|null $scopes List of scopes to grant
     *
     * @return static
     *
     * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.3.2
     *
     * @psalm-mutation-free
     */
    public function password(string $username, string $password, ?array $scopes = null): TokenEndPoint
    {
        $endpoint = clone $this;

        $endpoint->parameters['grant_type'] = self::GRANT_TYPE_PASSWORD;
        $endpoint->parameters['username'] = $username;
        $endpoint->parameters['password'] = $password;

        if ($scopes) {
            $endpoint->parameters['scope'] = implode(' ', $scopes);
        }

        return $endpoint;
    }

    /**
     * Configure the refresh token request
     *
     * @param string $token The refresh token
     * @param list<string>|null $scopes List of scopes to grant
     *
     * @return static
     *
     * @see https://datatracker.ietf.org/doc/html/rfc6749#section-6
     *
     * @psalm-mutation-free
     */
    public function refresh(string $token, ?array $scopes = null): TokenEndPoint
    {
        $endpoint = clone $this;

        $endpoint->parameters['grant_type'] = self::GRANT_TYPE_REFRESH;
        $endpoint->parameters['refresh_token'] = $token;

        if ($scopes) {
            $endpoint->parameters['scope'] = implode(' ', $scopes);
        }

        return $endpoint;
    }

    /**
     * {@inheritdoc}
     */
    public function call(): TokenResponse
    {
        $client = $this->client;
        $endPoints = $client->endPoints();
        $request = $endPoints->request('POST', $this);
        $authenticationMethod = $endPoints->authenticationMethod($this->name(), $client->option(ClientAuthenticationMethodInterface::OPTION_PREFERRED_METHOD));

        $request = $authenticationMethod->apply($client, $request);

        $body = (string) $client->provider()->sendRequest($request)->getBody();
        $response = ($this->responseFactory)(json_decode($body, true));

        $this->callResponseListeners($response);

        return $response;
    }

    /**
     * Change the token response factory
     * Factory prototype : function (array $body): TokenResponse
     *
     * @param callable(array):TokenResponse $factory
     *
     * @return static
     *
     * @psalm-mutation-free
     */
    public function responseFactory(callable $factory): TokenEndPoint
    {
        $endpoint = clone $this;
        $endpoint->responseFactory = $factory;

        return $endpoint;
    }
}
