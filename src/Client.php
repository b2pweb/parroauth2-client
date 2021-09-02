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
class Client implements ClientInterface
{
    /**
     * @var ProviderInterface
     */
    private $provider;

    /**
     * @var ClientConfig
     */
    private $clientConfig;

    /**
     * @var EndPoints
     */
    private $endPoints;

    /**
     * @var StorageInterface
     */
    private $session;


    /**
     * Client constructor.
     *
     * @param ProviderInterface $provider
     * @param ClientConfig $clientConfig
     * @param StorageInterface $session
     */
    public function __construct(ProviderInterface $provider, ClientConfig $clientConfig, StorageInterface $session)
    {
        $this->provider = $provider;
        $this->clientConfig = $clientConfig;
        $this->endPoints = new EndPoints($provider);
        $this->session = $session;
    }

    /**
     * Get the client id
     *
     * @return string
     */
    public function clientId(): string
    {
        return $this->clientConfig->clientId();
    }

    /**
     * Get the client secret.
     * May be null on a public client configuration
     *
     * @return string|null
     */
    public function secret(): ?string
    {
        return $this->clientConfig->secret();
    }

    /**
     * Get the client data storage
     *
     * @return StorageInterface
     */
    public function storage(): StorageInterface
    {
        return $this->session;
    }

    /**
     * Get the configuration of the client
     *
     * @return ClientConfig
     */
    public function clientConfig(): ClientConfig
    {
        return $this->clientConfig;
    }

    /**
     * Get the authorization provider
     *
     * @return ProviderInterface
     */
    public function provider(): ProviderInterface
    {
        return $this->provider;
    }

    /**
     * @return EndPoints
     */
    public function endPoints(): EndPoints
    {
        return $this->endPoints;
    }

    /**
     * Get the key set for the client
     *
     * @return JWKSet
     */
    public function keySet(): JWKSet
    {
        if ($jwks = $this->clientConfig->option('jwks')) {
            return $jwks;
        }

        return $this->provider->keySet();
    }

    /**
     * Get an option from client or provider
     *
     * @param string $name The option name
     * @param T|null $default The default value to return when not found on client and provider parameters
     *
     * @return T|null
     *
     * @template T
     */
    public function option(string $name, $default = null)
    {
        return $this->clientConfig->option($name, $this->provider->metadata($name, $default));
    }

    /**
     * Register extension
     *
     * @param ExtensionInterface $extension
     */
    public function register(ExtensionInterface $extension): void
    {
        $extension->configure($this);
    }
}
