<?php

namespace Parroauth2\Client\Tests;

use Http\Client\Common\HttpMethodsClient;
use Http\Discovery\HttpClientDiscovery;
use Http\Discovery\MessageFactoryDiscovery;
use Http\Discovery\Psr17FactoryDiscovery;
use Http\Discovery\Psr18ClientDiscovery;
use Parroauth2\Client\Client;
use Parroauth2\Client\ClientConfig;
use Parroauth2\Client\ClientInterface;
use Parroauth2\Client\Factory\BaseClientFactory;
use Parroauth2\Client\Provider\Provider;
use Parroauth2\Client\Provider\ProviderLoader;
use Parroauth2\Client\Storage\ArrayStorage;
use PHPUnit\Framework\TestCase;

/**
 * Class FunctionalTestCase
 */
class FunctionalTestCase extends TestCase
{
    /**
     * @var TestingDataSet
     */
    protected $dataSet;

    /**
     * @var Provider
     */
    protected $provider;

    /**
     * @var HttpMethodsClient
     */
    protected $httpClient;

    /**
     * @var ArrayStorage
     */
    protected $session;

    protected function setUp(): void
    {
        $this->dataSet = new TestingDataSet();
        $this->dataSet->declare();

        $this->session = new ArrayStorage();
        $this->httpClient = new HttpMethodsClient(
            new \Http\Client\Curl\Client(),
            Psr17FactoryDiscovery::findRequestFactory()
        );
        $this->provider = (new ProviderLoader(new BaseClientFactory($this->session), $this->httpClient))->discover('http://localhost:5000');
    }

    protected function tearDown(): void
    {
        $this->dataSet->destroy();
    }

    public function client(ClientConfig $config): ClientInterface
    {
        return $this->provider->client($config);
    }
}
