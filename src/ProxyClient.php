<?php

namespace Parroauth2\Client;

use Closure;
use Jose\Component\Core\JWKSet;
use Parroauth2\Client\EndPoint\EndPoints;
use Parroauth2\Client\Extension\ExtensionInterface;
use Parroauth2\Client\Provider\ProviderInterface;
use Parroauth2\Client\Provider\ProxyProvider;
use Parroauth2\Client\Storage\StorageInterface;

use function trigger_error;

/**
 * Lazy loading client implementation
 *
 * @see ProxyProvider For instantiate the ProxyClient
 */
final class ProxyClient implements ClientInterface
{
    private readonly ClientConfig $config;

    /**
     * @var Closure(ClientConfig):ClientInterface
     */
    private Closure $clientFactory;

    /**
     * @var list<ExtensionInterface>
     */
    private array $extensions = [];

    /**
     * @var ClientInterface|null
     */
    private ?ClientInterface $client = null;

    /**
     * ProxyClient constructor.
     *
     * @param ClientConfig $config The client configuration
     * @param callable(ClientConfig):ClientInterface $clientFactory
     */
    public function __construct(ClientConfig $config, callable $clientFactory)
    {
        $this->config = $config;

        if (!$clientFactory instanceof Closure) {
            @trigger_error('The client factory should be a Closure. This will be enforced in the v3.0.', E_USER_DEPRECATED);
            $clientFactory = $clientFactory(...);
        }

        $this->clientFactory = $clientFactory;
    }

    /**
     * {@inheritdoc}
     */
    public function clientId(): string
    {
        return $this->config->clientId();
    }

    /**
     * {@inheritdoc}
     */
    public function secret(): ?string
    {
        return $this->config->secret();
    }

    /**
     * {@inheritdoc}
     */
    public function storage(): StorageInterface
    {
        return $this->client()->storage();
    }

    /**
     * {@inheritdoc}
     */
    public function clientConfig(): ClientConfig
    {
        return $this->config;
    }

    /**
     * {@inheritdoc}
     */
    public function provider(): ProviderInterface
    {
        return $this->client()->provider();
    }

    /**
     * {@inheritdoc}
     */
    public function endPoints(): EndPoints
    {
        return $this->client()->endPoints();
    }

    /**
     * {@inheritdoc}
     */
    public function keySet(): JWKSet
    {
        return $this->client()->keySet();
    }

    /**
     * {@inheritdoc}
     */
    public function option(string $name, $default = null)
    {
        return $this->config->option($name, $default);
    }

    /**
     * {@inheritdoc}
     */
    public function register(ExtensionInterface $extension): void
    {
        if ($this->client) {
            $this->client->register($extension);
        } else {
            $this->extensions[] = $extension;
        }
    }

    /**
     * Resolve the real client instance
     *
     * @return ClientInterface
     */
    private function client(): ClientInterface
    {
        if ($this->client) {
            return $this->client;
        }

        $this->client = ($this->clientFactory)($this->config);

        foreach ($this->extensions as $extension) {
            $this->client->register($extension);
        }

        unset($this->clientFactory);
        unset($this->extensions);

        return $this->client;
    }
}
