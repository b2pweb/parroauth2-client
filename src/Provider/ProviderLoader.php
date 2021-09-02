<?php

namespace Parroauth2\Client\Provider;

use Http\Client\Common\HttpMethodsClient;
use Http\Client\HttpClient;
use Http\Discovery\HttpClientDiscovery;
use Http\Discovery\MessageFactoryDiscovery;
use Http\Message\RequestFactory;
use Parroauth2\Client\Factory\BaseClientFactory;
use Parroauth2\Client\Factory\ClientFactoryInterface;

/**
 * Load authorization providers
 *
 * <code>
 * $loader = new ProviderLoader();
 * $provider = $loader->discover('http://example.com');
 * $client = $provider->client(...);
 * </code>
 */
final class ProviderLoader
{
    /**
     * List of well-known paths
     * The first element is the path, and the second is a boolean for define if the server supports open id connect
     *
     * @var list<array{0:string, 1:bool}>
     */
    private $wellKnownUris = [
        ['openid-configuration', true],
        ['oauth-authorization-server', false],
    ];

    /**
     * @var ClientFactoryInterface
     */
    private $clientFactory;

    /**
     * @var HttpClient
     */
    private $httpClient;

    /**
     * @var RequestFactory
     */
    private $messageFactory;

    /**
     * @var ProviderConfigPool
     */
    private $configPool;


    /**
     * ProviderLoader constructor.
     *
     * @param ClientFactoryInterface|null $clientFactory
     * @param HttpClient|null $httpClient The HTTP client to use. If null will discover registered clients
     * @param RequestFactory|null $messageFactory The HTTP message factory to use.
     *     If null will discover registered factories
     * @param ProviderConfigPool|null $configPool
     */
    public function __construct(ClientFactoryInterface $clientFactory = null, HttpClient $httpClient = null, RequestFactory $messageFactory = null, ProviderConfigPool $configPool = null)
    {
        $this->clientFactory = $clientFactory ?: new BaseClientFactory();
        $this->httpClient = $httpClient ?: HttpClientDiscovery::find();
        /** @psalm-suppress DeprecatedClass */
        $this->messageFactory = $messageFactory ?: MessageFactoryDiscovery::find();
        $this->configPool = $configPool ?: new ProviderConfigPool();
    }

    /**
     * Creates the provider using the well known URI for get server metadata
     *
     * @param string $providerUrl
     *
     * @return ProviderInterface
     *
     * @throws \Http\Client\Exception
     *
     * @see ProviderLoader::lazy() For perform a lazy loading of the metadata
     *
     * @psalm-suppress InvalidThrow
     */
    public function discover(string $providerUrl): ProviderInterface
    {
        if ($config = $this->configPool->get($providerUrl)) {
            return $this->create($config);
        }

        $client = new HttpMethodsClient($this->httpClient, $this->messageFactory);

        foreach ($this->wellKnownUris as list($uri, $openid)) {
            $response = $client->get($providerUrl . '/.well-known/' . $uri);

            if ($response->getStatusCode() !== 200) {
                continue;
            }

            $config = $this->configPool->createFromJson($providerUrl, (string) $response->getBody(), $openid);
            $config->save();

            return $this->create($config);
        }

        throw new \InvalidArgumentException('Authorization provider discovery is not supported by the server');
    }

    /**
     * Creates the provider using server metadata, but loaded in lazy way
     *
     * @param string $providerUrl The base provider URL
     *
     * @return ProviderInterface
     *
     * @see ProviderLoader::discover() Non-lazy provider creation method
     */
    public function lazy(string $providerUrl): ProviderInterface
    {
        return new ProxyProvider($providerUrl, $this);
    }

    /**
     * Creates a provider using a config
     * The configuration format must follow the server metadata form
     *
     * @param array<string, mixed>|ProviderConfig $config The provider configuration
     * @param bool|null $openid Does the provider supports openid ?
     *
     * @return ProviderInterface
     *
     * @see ProviderLoader::builder() For simple configuration of the provider
     *
     * @see https://openid.net/specs/openid-connect-discovery-1_0.html The OpenID Connect metadata
     * @see https://tools.ietf.org/html/rfc8414 The OAuth 2.0 server metadata
     */
    public function create($config, ?bool $openid = null): ProviderInterface
    {
        if (!$config instanceof ProviderConfig) {
            $config = $this->configPool->createFromArray($config, $openid);
        }

        return new Provider($this->clientFactory, $this->httpClient, $this->messageFactory, $config);
    }

    /**
     * Get a provider builder for manual configuration of the provider
     *
     * <code>
     * $provider = $loader->builder('http://op.example.com')
     *     ->authorizationEndPoint('/authorize')
     *     ->tokenEndPoint('/token')
     *     ->addKeyFile('/path/to/rsa.key')
     *     ->openid()
     *     ->create()
     * ;
     * </code>
     *
     * @param string $url The base URL of the provider
     *
     * @return ProviderBuilder
     *
     * @see ProviderLoader::create() For creation without builder
     */
    public function builder(string $url): ProviderBuilder
    {
        return new ProviderBuilder($this, $this->configPool, $url);
    }
}
