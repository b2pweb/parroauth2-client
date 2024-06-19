<?php

namespace Parroauth2\Client\Authentication;

use Parroauth2\Client\ClientInterface;
use Parroauth2\Client\EndPoint\EndPoints;
use Psr\Http\Message\RequestInterface;

/**
 * Type representing how the client is authenticated on identity provider endpoints
 * like token, introspection, revocation, ...
 */
interface ClientAuthenticationMethodInterface
{
    /**
     * Option for defining the preferred authentication method
     *
     * @see ClientInterface::option() To get the option value
     * @see EndPoints::authenticationMethod() This option is used as second argument
     */
    public const OPTION_PREFERRED_METHOD = 'preferred_auth_method';

    /**
     * Apply the authentication parameters to the request
     *
     * @param ClientInterface $client Client to authenticate
     * @param RequestInterface $request The request to authenticate
     *
     * @return RequestInterface The authenticated request
     */
    public function apply(ClientInterface $client, RequestInterface $request): RequestInterface;

    /**
     * Define available signing algorithms
     *
     * This value should be provided by the server metadata, on key `*_endpoint_auth_signing_alg_values_supported`
     * A new instance of the method should be returned, with the new algorithms filter
     *
     * If the method does not support signing algorithms, it should return itself
     *
     * @param list<string> $algorithms
     *
     * @return self The new instance with the new algorithms filter, or $this if the method does not support signing
     */
    public function withSigningAlgorithms(array $algorithms): self;

    /**
     * The name of the authentication method
     * Usually its defined as NAME constant
     */
    public function name(): string;
}
