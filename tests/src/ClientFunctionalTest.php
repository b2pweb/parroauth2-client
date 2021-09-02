<?php

namespace Parroauth2\Client;

use Jose\Component\Core\JWKSet;
use Parroauth2\Client\EndPoint\EndPoints;
use Parroauth2\Client\Tests\FunctionalTestCase;

/**
 * Class ClientFunctionalTest
 */
class ClientFunctionalTest extends FunctionalTestCase
{
    /**
     * @var Client
     */
    protected $client;

    protected function setUp(): void
    {
        parent::setUp();

        $this->client = $this->client(
            (new ClientConfig('test'))
                ->setSecret('my-secret')
                ->setScopes(['email', 'name'])
                ->enableOpenId(false)
        );
        $this->dataSet
            ->pushClient('test', 'my-secret', 'http://client.example.com')
            ->pushUser('bob', '$bob')
            ->pushScopes(['email', 'name'])
        ;
    }

    /**
     *
     */
    public function test_getters()
    {
        $this->assertEquals('test', $this->client->clientId());
        $this->assertEquals($this->session, $this->client->storage());
        $this->assertEquals('my-secret', $this->client->secret());
        $this->assertEquals($this->provider, $this->client->provider());
        $this->assertInstanceOf(EndPoints::class, $this->client->endPoints());
    }

    /**
     *
     */
    public function test_keySet()
    {
        $this->assertSame($this->provider->keySet(), $this->client->keySet());

        $jwks = new JWKSet([]);
        $this->client->clientConfig()->setOption('jwks', $jwks);
        $this->assertSame($jwks, $this->client->keySet());
    }
}
