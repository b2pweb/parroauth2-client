<?php

namespace Parroauth2\Client\Provider;

use Http\Client\Common\HttpMethodsClient;
use Http\Client\HttpClient;
use Http\Discovery\HttpClientDiscovery;
use Http\Discovery\MessageFactoryDiscovery;
use Http\Message\MessageFactory;
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
 *
 * @todo cache system
 */
class ProviderLoader
{
    /**
     * List of well-known paths
     * The first element is the path, and the second is a boolean for define if the server supports open id connect
     *
     * @var array
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
     * @var MessageFactory
     */
    private $messageFactory;

    /**
     * Discovered providers indexed  by there URL
     *
     * @var Provider[]
     */
    private $cache;


    /**
     * ProviderLoader constructor.
     *
     * @param ClientFactoryInterface $clientFactory
     * @param HttpClient|null $httpClient The HTTP client to use. If null will discover registered clients
     * @param MessageFactory|null $messageFactory The HTTP message factory to use. If null will discover registered factories
     */
    public function __construct(ClientFactoryInterface $clientFactory = null, HttpClient $httpClient = null, MessageFactory $messageFactory = null)
    {
        $this->clientFactory = $clientFactory ?: new BaseClientFactory();
        $this->httpClient = $httpClient ?: HttpClientDiscovery::find();
        $this->messageFactory = $messageFactory ?: MessageFactoryDiscovery::find();
    }

    /**
     * Creates the provider using the well known URI for get server metadata
     *
     * @param string $providerUrl
     *
     * @return Provider
     *
     * @throws \Http\Client\Exception
     */
    public function discover(string $providerUrl): Provider
    {
        if (isset($this->cache[$providerUrl])) {
            return $this->cache[$providerUrl];
        }

        $client = new HttpMethodsClient($this->httpClient, $this->messageFactory);

        foreach ($this->wellKnownUris as list($uri, $openid)) {
            $response = $client->get($providerUrl.'/.well-known/'.$uri);

            if ($response->getStatusCode() !== 200) {
                continue;
            }

            $config = json_decode($response->getBody(), true);

            return $this->cache[$providerUrl] = $this->create($config, $openid);
        }

        throw new \InvalidArgumentException('Authorization provider discovery is not supported by the server');
    }

    /**
     * Creates a provider using a config
     * The configuration format must follow the server metadata form
     *
     * @param array $config The provider configuration
     * @param bool $openid Does the provider supports openid ?
     *
     * @return Provider
     *
     * @see https://openid.net/specs/openid-connect-discovery-1_0.html The OpenID Connect metadata
     * @see https://tools.ietf.org/html/rfc8414 The OAuth 2.0 server metadata
     */
    public function create(array $config, bool $openid): Provider
    {
        return new Provider($this->clientFactory, $this->httpClient, $this->messageFactory, $config, $openid);
    }
}
