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
}
