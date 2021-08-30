<?php

namespace Parroauth2\Client;

use Jose\Component\Core\JWKSet;
use Parroauth2\Client\EndPoint\EndPoints;
use Parroauth2\Client\Extension\ExtensionInterface;
use Parroauth2\Client\Provider\ProviderInterface;
use Parroauth2\Client\Storage\StorageInterface;

/**
 * The oauth2 client
 */
interface ClientInterface
{
    /**
     * Get the client id
     *
     * @return string
     */
    public function clientId(): string;

    /**
     * Get the client secret.
     * May be null on a public client configuration
     *
     * @return string|null
     */
    public function secret(): ?string;

    /**
     * Get the client data storage
     *
     * @return StorageInterface
     */
    public function storage(): StorageInterface;

    /**
     * Get the configuration of the client
     *
     * @return ClientConfig
     */
    public function clientConfig(): ClientConfig;

    /**
     * Get the authorization provider
     *
     * @return ProviderInterface
     */
    public function provider(): ProviderInterface;

    /**
     * @return EndPoints
     * @psalm-allow-private-mutation
     */
    public function endPoints(): EndPoints;

    /**
     * Get the key set for the client
     *
     * @return JWKSet
     */
    public function keySet(): JWKSet;

    /**
     * Get an option from client or provider
     *
     * @param string $name The option name
     * @param mixed $default The default value to return when not found on client and provider parameters
     *
     * @return mixed
     */
    public function option(string $name, $default = null);

    /**
     * Register extension
     *
     * @param ExtensionInterface $extension
     */
    public function register(ExtensionInterface $extension): void;

    /**
     * Request for token from username / password
     *
     * @param string $username
     * @param string $password
     * @param null|string[] $scopes
     *
     * @return Authorization
     *
     * @deprecated Use token endpoint
     * @psalm-suppress DeprecatedClass
     */
    public function login($username, $password, array $scopes = null);

    /**
     * Refresh the token
     *
     * @param Authorization|string $token
     * @param null|string[] $scopes
     *
     * @return Authorization
     *
     * @deprecated Use token endpoint
     * @psalm-suppress DeprecatedClass
     */
    public function refresh($token, array $scopes = null);

    /**
     * Request the token from authorization code
     *
     * @param string $code
     * @param null|string $redirectUri
     * @param null|string $clientId
     *
     * @return Authorization
     *
     * @deprecated Use AuthorizationCodeFlow or token endpoint
     * @psalm-suppress DeprecatedClass
     */
    public function tokenFromAuthorizationCode($code, $redirectUri = null, $clientId = null);

    /**
     * Get the authorization uri
     *
     * @param string $redirectUri
     * @param null|string[] $scopes
     * @param null|string $state
     * @param null|string $clientId
     * @param array<string, mixed> $parameters
     *
     * @return string
     *
     * @deprecated Use AuthorizationCodeFlow or authorization endpoint
     * @psalm-suppress DeprecatedClass
     */
    public function getAuthorizationUri($redirectUri, array $scopes = null, $state = null, $clientId = null, array $parameters = []);

    /**
     * Introspect a token
     *
     * @param Authorization|string $token
     * @param string $hint
     *
     * @return Introspection
     *
     * @deprecated Use introspection endpoint
     * @psalm-suppress DeprecatedClass
     */
    public function introspect($token, $hint = null);

    /**
     * Revoke the token
     *
     * @param Authorization|string $token
     * @param string|null $hint
     *
     * @return void
     *
     * @deprecated Use revocation endpoint
     * @psalm-suppress DeprecatedClass
     */
    public function revoke($token, $hint = null);

    /**
     * Gets user info from the access token
     *
     * @param string|Authorization $token
     *
     * @return Userinfo
     *
     * @deprecated Use userinfo endpoint
     * @psalm-suppress DeprecatedClass
     */
    public function userinfo($token);
}
