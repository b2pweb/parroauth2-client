<?php

namespace Parroauth2\Client;

use Parroauth2\Client\EndPoint\EndPoints;
use Parroauth2\Client\Extension\ExtensionInterface;
use Parroauth2\Client\Factory\BaseClientFactory;
use Parroauth2\Client\Provider\ProviderLoader;

/**
 * Class ProxyClientFunctionalTest
 */
class ProxyClientFunctionalTest extends ClientFunctionalTest
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->provider = (new ProviderLoader(new BaseClientFactory($this->session)))->lazy('http://localhost:5000');
        $this->client = $this->provider->client(
            (new ClientConfig('test'))
                ->setSecret('my-secret')
                ->setScopes(['email', 'name'])
                ->enableOpenId(false)

        );
    }

    /**
     *
     */
    public function test_getters()
    {
        $this->assertEquals('test', $this->client->clientId());
        $this->assertEquals($this->session, $this->client->storage());
        $this->assertEquals('my-secret', $this->client->secret());
        $this->assertInstanceOf(EndPoints::class, $this->client->endPoints());
    }

    /**
     *
     */
    public function test_register_not_initialized()
    {
        $e1 = $this->createMock(ExtensionInterface::class);
        $e2 = $this->createMock(ExtensionInterface::class);

        $e1->expects($this->never())->method('configure');
        $e2->expects($this->never())->method('configure');

        $this->client->register($e1);
        $this->client->register($e2);
    }

    /**
     *
     */
    public function test_register_on_initialization()
    {
        $e1 = $this->createMock(ExtensionInterface::class);
        $e2 = $this->createMock(ExtensionInterface::class);

        $this->client->register($e1);
        $this->client->register($e2);

        $e1->expects($this->once())->method('configure');
        $e2->expects($this->once())->method('configure');

        $this->client->provider(); // Initialize client

        $e3 = $this->createMock(ExtensionInterface::class);

        $e3->expects($this->once())->method('configure');
        $this->client->register($e3);
    }
}
