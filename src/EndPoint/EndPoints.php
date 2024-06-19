<?php

namespace Parroauth2\Client\EndPoint;

use InvalidArgumentException;
use Parroauth2\Client\Authentication\BasicClientAuthenticationMethod;
use Parroauth2\Client\Authentication\ClientAuthenticationMethodInterface;
use Parroauth2\Client\EndPoint\Authorization\AuthorizationEndPoint;
use Parroauth2\Client\EndPoint\Introspection\IntrospectionEndPoint;
use Parroauth2\Client\EndPoint\Token\RevocationEndPoint;
use Parroauth2\Client\EndPoint\Token\TokenEndPoint;
use Parroauth2\Client\Exception\UnsupportedServerOperation;
use Parroauth2\Client\OpenID\EndPoint\EndSessionEndPoint;
use Parroauth2\Client\OpenID\EndPoint\Userinfo\UserinfoEndPoint;
use Parroauth2\Client\Provider\Provider;
use Parroauth2\Client\Provider\ProviderInterface;
use Psr\Http\Message\RequestInterface;

use function in_array;
use function method_exists;

/**
 * Store endpoints
 */
class EndPoints
{
    /**
     * @var ProviderInterface
     * @readonly
     */
    private $provider;

    /**
     * List of registered endpoints, indexed by name
     *
     * @var EndPointInterface[]
     */
    private $endpoints = [];

    /**
     * @var EndPointTransformerInterface[]
     */
    private $extensions = [];

    /**
     * EndPointsSet constructor.
     *
     * @param ProviderInterface $provider
     */
    public function __construct(ProviderInterface $provider)
    {
        $this->provider = $provider;
    }

    /**
     * Get an endpoint, and apply extensions
     *
     * @param string $name The endpoint name
     *
     * @return EndPointInterface
     *
     * @throws InvalidArgumentException When the client do not implements the endpoint
     */
    public function get(string $name): EndPointInterface
    {
        if (!isset($this->endpoints[$name])) {
            throw new InvalidArgumentException('The endpoint "' . $name . '" is not implemented');
        }

        $endpoint = $this->endpoints[$name];

        foreach ($this->extensions as $extension) {
            $endpoint = $endpoint->apply($extension);
        }

        return $endpoint;
    }

    /**
     * Generates the URI for an endpoint
     *
     * @param EndPointInterface $endpoint
     *
     * @return string
     *
     * @throws UnsupportedServerOperation When the server is not configured for supports the endpoint
     *
     * @see Provider::uri() For generate lower level URI
     */
    public function uri(EndPointInterface $endpoint): string
    {
        return $this->provider->uri($endpoint->name(), $endpoint->parameters());
    }

    /**
     * Create a request for the endpoint
     * The endpoint name is used for generates the URI
     * The parameters are set as query parameters for GET request, or as body with other methods
     *
     * @param string $method The HTTP method
     * @param EndPointInterface $endpoint The endpoint
     *
     * @return RequestInterface
     *
     * @throws UnsupportedServerOperation When the server is not configured for supports the endpoint
     *
     * @see Provider::request() For create lower level request
     */
    public function request(string $method, EndPointInterface $endpoint): RequestInterface
    {
        $isGet = $method === 'GET';
        $parameters = $endpoint->parameters();

        $request = $this->provider->request(
            $method,
            $endpoint->name(),
            $isGet ? $parameters : [],
            $isGet ? null : $parameters
        );

        if (!$isGet && $parameters) {
            $request = $request->withHeader('Content-Type', 'application/x-www-form-urlencoded');
        }

        return $request;
    }

    /**
     * Add an endpoint to the set
     *
     * @param EndPointInterface $endPoint
     */
    public function add(EndPointInterface $endPoint): void
    {
        $this->endpoints[$endPoint->name()] = $endPoint;
    }

    /**
     * Register a new extension
     *
     * @param EndPointTransformerInterface $extension
     */
    public function register(EndPointTransformerInterface $extension): void
    {
        $this->extensions[] = $extension;
    }

    /**
     * Get the authorization endpoint
     *
     * @throws UnsupportedServerOperation When the server is not configured for supports the endpoint
     * @throws InvalidArgumentException When the client do not implements the endpoint
     */
    public function authorization(): AuthorizationEndPoint
    {
        /** @var AuthorizationEndPoint */
        return $this->get(AuthorizationEndPoint::NAME);
    }

    /**
     * Get the token endpoint
     *
     * @throws UnsupportedServerOperation When the server is not configured for supports the endpoint
     * @throws InvalidArgumentException When the client do not implements the endpoint
     */
    public function token(): TokenEndPoint
    {
        /** @var TokenEndPoint */
        return $this->get(TokenEndPoint::NAME);
    }

    /**
     * Get the revocation endpoint
     *
     * @throws UnsupportedServerOperation When the server is not configured for supports the endpoint
     * @throws InvalidArgumentException When the client do not implements the endpoint
     */
    public function revocation(): RevocationEndPoint
    {
        /** @var RevocationEndPoint */
        return $this->get(RevocationEndPoint::NAME);
    }

    /**
     * Get the introspection endpoint
     *
     * @throws UnsupportedServerOperation When the server is not configured for supports the endpoint
     * @throws InvalidArgumentException When the client do not implements the endpoint
     */
    public function introspection(): IntrospectionEndPoint
    {
        /** @var IntrospectionEndPoint */
        return $this->get(IntrospectionEndPoint::NAME);
    }

    /**
     * Get the userinfo endpoint
     *
     * @throws UnsupportedServerOperation When the server is not configured for supports the endpoint
     * @throws InvalidArgumentException When the client do not implements the endpoint
     */
    public function userinfo(): UserinfoEndPoint
    {
        /** @var UserinfoEndPoint */
        return $this->get(UserinfoEndPoint::NAME);
    }

    /**
     * Get the endSession endpoint
     *
     * @throws UnsupportedServerOperation When the server is not configured for supports the endpoint
     * @throws InvalidArgumentException When the client do not implements the endpoint
     */
    public function endSession(): EndSessionEndPoint
    {
        /** @var EndSessionEndPoint */
        return $this->get(EndSessionEndPoint::NAME);
    }

    /**
     * Get the client authentication method to use for an endpoint
     *
     * The method is resolved by the following steps:
     * - Get all supported methods using {@see ProviderInterface::availableAuthenticationMethods()}
     * - Filter methods using the provider metadata "{endpoint}_endpoint_auth_methods_supported". If the metadata is not available, no filter is applied.
     * - If a preferred method is specified, and it's supported by the endpoint, use it.
     * - Else, use the first method of "{endpoint}_endpoint_auth_methods_supported", if available.
     * - Else, use the "client_secret_basic" method.
     *
     * Once the method is selected, the provider metadata "{endpoint}_endpoint_auth_signing_alg_values_supported" is used to filter the supported algorithms.
     * If it's present, {@see ClientAuthenticationMethodInterface::withSigningAlgorithms()} is used to filter the algorithms.
     *
     * @param string $endPoint The endpoint name
     * @param string|null $preferredMethod The preferred method name. If null, the first supported method is used. Use {@see ClientAuthenticationMethodInterface::OPTION_PREFERRED_METHOD} to specify a preferred method.
     *
     * @return ClientAuthenticationMethodInterface The selected method
     */
    public function authenticationMethod(string $endPoint, ?string $preferredMethod = null): ClientAuthenticationMethodInterface
    {
        $provider = $this->provider;

        $methods = method_exists($provider, 'availableAuthenticationMethods') ? $provider->availableAuthenticationMethods() : [];
        $supportedMethodNames = $provider->metadata($endPoint . '_endpoint_auth_methods_supported');
        $supportedAlgorithms = $provider->metadata($endPoint . '_endpoint_auth_signing_alg_values_supported');

        $supportedMethods = [];

        // Filter methods supported by the server, and indexed by name
        foreach ($methods as $method) {
            if ($supportedMethodNames === null || in_array($method->name(), $supportedMethodNames, true)) {
                $supportedMethods[$method->name()] = $method;
            }
        }

        if ($preferredMethod && isset($supportedMethods[$preferredMethod])) {
            // If a preferred method is requested and is supported, use it
            $selectedMethod = $supportedMethods[$preferredMethod];
        } elseif (isset($supportedMethodNames[0]) && isset($supportedMethods[$supportedMethodNames[0]])) {
            // Else, use the first supported method
            $selectedMethod = $supportedMethods[$supportedMethodNames[0]];
        } else {
            // If no method are supported, use the basic method
            $selectedMethod = $supportedMethods[BasicClientAuthenticationMethod::NAME] ?? new BasicClientAuthenticationMethod();
        }

        // Specify supported algorithms, if any
        return $supportedAlgorithms ? $selectedMethod->withSigningAlgorithms($supportedAlgorithms) : $selectedMethod;
    }
}
