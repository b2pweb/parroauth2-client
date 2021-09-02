<?php

namespace Parroauth2\Client\EndPoint\Authorization;

use Base64Url\Base64Url;
use Parroauth2\Client\Client;
use Parroauth2\Client\ClientInterface;
use Parroauth2\Client\EndPoint\EndPointInterface;
use Parroauth2\Client\EndPoint\EndPointParametersTrait;
use Parroauth2\Client\EndPoint\EndPointTransformerInterface;
use Parroauth2\Client\Exception\UnsupportedServerOperation;

/**
 * The authorization endpoint
 * This endpoint must be called by the user agent using a redirection
 *
 * @see https://tools.ietf.org/html/rfc6749#section-3.1
 */
class AuthorizationEndPoint implements EndPointInterface
{
    use EndPointParametersTrait;

    public const NAME = 'authorization';

    public const RESPONSE_TYPE_CODE = 'code';
    public const RESPONSE_TYPE_TOKEN = 'token';

    /**
     * @var ClientInterface
     * @readonly
     */
    private $client;

    /**
     * AuthorizationEndPoint constructor.
     *
     * @param ClientInterface $client
     */
    public function __construct(ClientInterface $client)
    {
        $this->client = $client;
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
     *
     * @return static
     */
    public function apply(EndPointTransformerInterface $transformer): AuthorizationEndPoint
    {
        return $transformer->onAuthorization($this);
    }

    /**
     * Authorization request for get an authorization code (i.e. response_type=code)
     *
     * @param string|null $redirectUri The URI to redirect after authorization
     * @param string[] $scopes List of scopes
     *
     * @return static
     *
     * @see https://tools.ietf.org/html/rfc6749#section-4.1.1
     */
    public function code(?string $redirectUri = null, array $scopes = []): AuthorizationEndPoint
    {
        $endpoint = clone $this;

        $endpoint->parameters['client_id'] = $endpoint->client->clientId();
        $endpoint->parameters['response_type'] = self::RESPONSE_TYPE_CODE;

        if ($redirectUri) {
            $endpoint->parameters['redirect_uri'] = $redirectUri;
        }

        if ($scopes) {
            $endpoint = $endpoint->scope($scopes);
        }

        if (empty($endpoint->parameters['state'])) {
            $endpoint = $endpoint->state();
        }

        return $endpoint;
    }

    /**
     * Define scopes
     *
     * @param string[] $scopes
     *
     * @return static
     *
     * @psalm-mutation-free
     */
    public function scope(array $scopes): AuthorizationEndPoint
    {
        return $this->set('scope', implode(' ', $scopes));
    }

    /**
     * Define a state
     * The state will be saved into the client session
     *
     * @param string|null $state The state, or null to generates the state
     *
     * @return static
     */
    public function state(?string $state = null): AuthorizationEndPoint
    {
        $endpoint = clone $this;

        if ($state === null) {
            $state = Base64Url::encode(random_bytes(32));
        }

        $endpoint->parameters['state'] = $state;

        return $endpoint;
    }

    /**
     * Generates the authorization URI
     *
     * @return string
     * @throws UnsupportedServerOperation
     */
    public function uri(): string
    {
        return $this->client->endPoints()->uri($this);
    }
}
