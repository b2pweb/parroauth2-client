<?php

namespace Parroauth2\Client\EndPoint\Token;

use Http\Client\Exception;
use Parroauth2\Client\Client;
use Parroauth2\Client\ClientInterface;
use Parroauth2\Client\EndPoint\EndPointInterface;
use Parroauth2\Client\EndPoint\EndPointParametersTrait;
use Parroauth2\Client\EndPoint\EndPointResponseListenerTrait;
use Parroauth2\Client\EndPoint\EndPointTransformerInterface;
use Parroauth2\Client\Exception\Parroauth2Exception;

/**
 * Endpoint for generates an access token
 *
 * @see https://tools.ietf.org/html/rfc6749#section-5.1
 */
class TokenEndPoint implements EndPointInterface
{
    use EndPointParametersTrait;
    use EndPointResponseListenerTrait;

    const NAME = 'token';

    const GRANT_TYPE_CODE = 'authorization_code';
    const GRANT_TYPE_PASSWORD = 'password';
    const GRANT_TYPE_REFRESH = 'refresh_token';

    /**
     * @var ClientInterface
     */
    private $client;

    /**
     * @var callable
     */
    private $responseFactory;

    /**
     * @var callable[]
     */
    private $responseListeners = [];


    /**
     * TokenEndPoint constructor.
     *
     * @param ClientInterface $client
     * @param callable $responseFactory
     */
    public function __construct(ClientInterface $client, callable $responseFactory = null)
    {
        $this->client = $client;
        $this->responseFactory = $responseFactory ?: function (array $response) { return new TokenResponse($response); };
    }

    /**
     * {@inheritdoc}
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
     * @see https://tools.ietf.org/html/rfc6749#section-4.1.3
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
     * Configure a grant type password token request
     *
     * @param string $username The resource owner username
     * @param string $password The resource owner password
     * @param array|null $scopes List of scopes to grant
     *
     * @return static
     *
     * @see https://tools.ietf.org/html/rfc6749#section-4.3.2
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
     * @param array|null $scopes List of scopes to grant
     *
     * @return static
     *
     * @see https://tools.ietf.org/html/rfc6749#section-6
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
     * Call the endpoint
     *
     * @return TokenResponse The tokens
     *
     * @throws Parroauth2Exception When an error occurs during execution
     * @throws Exception
     *
     * @todo Handle other client credentials
     */
    public function call(): TokenResponse
    {
        $request = $this->client->endPoints()
            ->request('POST', $this)
            ->withHeader('Authorization', 'Basic '.base64_encode($this->client->clientId().':'.$this->client->secret()))
        ;

        $response = ($this->responseFactory)(json_decode($this->client->provider()->sendRequest($request)->getBody(), true));

        $this->callResponseListeners($response);

        return $response;
    }

    /**
     * Change the token response factory
     * Factory prototype : function (array $body): TokenResponse
     *
     * @param callable $factory
     *
     * @return static
     */
    public function responseFactory(callable $factory): TokenEndPoint
    {
        $endpoint = clone $this;
        $endpoint->responseFactory = $factory;

        return $endpoint;
    }
}
