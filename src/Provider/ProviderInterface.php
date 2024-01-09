<?php

namespace Parroauth2\Client\Provider;

use Jose\Component\Core\JWKSet;
use Parroauth2\Client\Authentication\ClientAuthenticationMethodInterface;
use Parroauth2\Client\ClientConfig;
use Parroauth2\Client\ClientInterface;
use Parroauth2\Client\Exception\Parroauth2Exception;
use Parroauth2\Client\Exception\UnsupportedServerOperation;
use Psr\Http\Client\ClientInterface as PsrClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

/**
 * The authorization provider
 *
 * Handle the HTTP operations, and create clients
 *
 * @method ClientAuthenticationMethodInterface[] availableAuthenticationMethods()
 */
interface ProviderInterface extends PsrClientInterface
{
    /**
     * Check if the provider supports OpenID Connect
     *
     * @return bool
     */
    public function openid(): bool;

    /**
     * Get the issuer value for the provider
     * The issuer is the base URL of the provider
     *
     * @return string
     */
    public function issuer(): string;

    /**
     * Get a server metadata parameter
     *
     * @param string $parameter The parameter name
     * @param T|null $default Default value to return if the parameter is not found
     *
     * @return T|null The parameter value
     * @psalm-return ($default is null ? mixed|null : T)
     *
     * @template T
     */
    public function metadata(string $parameter, $default = null);

    /**
     * Check if the provider supports the given endpoint
     *
     * @param string $name The endpoint name
     *
     * @return bool
     */
    public function supportsEndpoint(string $name): bool;

    /**
     * Generates the URI for an endpoint
     *
     * @param string $name The endpoint name
     * @param array $queryParameters The query parameters
     *
     * @return string
     * @throws UnsupportedServerOperation When the server is not configured for supports the endpoint
     */
    public function uri(string $name, array $queryParameters = []): string;

    /**
     * Creates a new http request
     *
     * @param string $method The HTTP method
     * @param string $endpoint The endpoint name
     * @param array $queryParameters The query parameters
     * @param resource|string|StreamInterface|array|object|null $body The body
     *
     * @return RequestInterface
     * @throws UnsupportedServerOperation
     */
    public function request(string $method, string $endpoint, array $queryParameters = [], $body = null): RequestInterface;

    /**
     * {@inheritdoc}
     *
     * @throws Parroauth2Exception When a server error occurs
     */
    public function sendRequest(RequestInterface $request): ResponseInterface;

    /**
     * Creates a client for the provider
     *
     * @param ClientConfig $config
     *
     * @return ClientInterface
     */
    public function client(ClientConfig $config): ClientInterface;

    /**
     * Get the keyset (jwks) of the provider
     *
     * @return JWKSet
     *
     * @throws Parroauth2Exception When a server error occurs
     * @throws \Http\Client\Exception
     *
     * @psalm-suppress InvalidThrow
     */
    public function keySet(): JWKSet;

    /**
     * Get the available authentication methods for the provider
     * Those method should be filtered according to metadata "*_endpoint_auth_methods_supported" parameters
     *
     * So this method may return authentication methods which are not supported by any endpoint
     *
     * @return ClientAuthenticationMethodInterface[] Authentication methods. Do not rely on the order or the keys.
     */
    //public function availableAuthenticationMethods(): array;
}
