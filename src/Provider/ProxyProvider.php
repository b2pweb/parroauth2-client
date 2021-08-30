<?php

namespace Parroauth2\Client\Provider;

use Jose\Component\Core\JWKSet;
use Parroauth2\Client\Client;
use Parroauth2\Client\ClientConfig;
use Parroauth2\Client\ClientInterface;
use Parroauth2\Client\ProxyClient;
use Psr\Http\Message\RequestInterface;

/**
 * Lazy loading implementation of the provider
 */
final class ProxyProvider implements ProviderInterface
{
    /**
     * @var string|null
     */
    private $url;

    /**
     * @var ProviderLoader|null
     */
    private $loader;

    /**
     * @var ProviderInterface|null
     */
    private $provider;


    /**
     * ProxyProvider constructor.
     *
     * @param string $url
     * @param ProviderLoader $loader
     */
    public function __construct(string $url, ProviderLoader $loader)
    {
        $this->url = $url;
        $this->loader = $loader;
    }

    /**
     * {@inheritdoc}
     */
    public function openid(): bool
    {
        return $this->provider()->openid();
    }

    /**
     * {@inheritdoc}
     */
    public function issuer(): string
    {
        return $this->provider()->issuer();
    }

    /**
     * {@inheritdoc}
     */
    public function metadata(string $parameter, $default = null)
    {
        return $this->provider()->metadata($parameter, $default);
    }

    /**
     * {@inheritdoc}
     */
    public function supportsEndpoint(string $name): bool
    {
        return $this->provider()->supportsEndpoint($name);
    }

    /**
     * {@inheritdoc}
     */
    public function uri($name, array $queryParameters = []): string
    {
        return $this->provider()->uri($name, $queryParameters);
    }

    /**
     * {@inheritdoc}
     */
    public function request(string $method, string $endpoint, array $queryParameters = [], $body = null): RequestInterface
    {
        return $this->provider()->request($endpoint, $endpoint, $queryParameters, $body);
    }

    /**
     * {@inheritdoc}
     */
    public function sendRequest(RequestInterface $request)
    {
        return $this->provider()->sendRequest($request);
    }

    /**
     * {@inheritdoc}
     */
    public function client(ClientConfig $config): ClientInterface
    {
        return new ProxyClient($config, function (ClientConfig $config) {
            return $this->provider()->client($config);
        });
    }

    /**
     * {@inheritdoc}
     */
    public function keySet(): JWKSet
    {
        return $this->provider()->keySet();
    }

    /**
     * Get the real provider instance
     *
     * @return ProviderInterface
     *
     * @psalm-suppress PossiblyNullReference
     * @psalm-suppress PossiblyNullArgument
     */
    private function provider(): ProviderInterface
    {
        if ($this->provider) {
            return $this->provider;
        }

        $this->provider = $this->loader->discover($this->url);
        $this->loader = null;
        $this->url = null;

        return $this->provider;
    }
}
