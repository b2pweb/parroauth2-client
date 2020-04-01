<?php

namespace Parroauth2\Client\Provider;

use GuzzleHttp\Psr7\Response;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use Parroauth2\Client\Client;
use Parroauth2\Client\ClientConfig;
use Parroauth2\Client\Factory\BaseClientFactory;
use Parroauth2\Client\Tests\UnitTestCase;

/**
 * Class ProxyProviderTest
 */
class ProxyProviderTest extends UnitTestCase
{
    /**
     * @var ProviderInterface
     */
    private $provider;

    protected function setUp(): void
    {
        parent::setUp();

        $loader = new ProviderLoader(new BaseClientFactory($this->session), $this->httpClient);
        $this->httpClient->addResponse(new Response(200, [], json_encode([
            'issuer' => 'http://provider.example.com',
            'authorization_endpoint' => 'http://provider.example.com/authorize',
            'jwks_uri' => 'http://provider.example.com/jwks.json',
            'foo' => 'bar',
        ])));

        $this->provider = $loader->lazy('http://provider.example.com');
    }

    /**
     *
     */
    public function test_provider_should_be_initialised_once()
    {
        $this->provider->openid();
        $this->provider->issuer();

        $this->assertCount(1, $this->httpClient->getRequests());
    }

    /**
     *
     */
    public function test_getters()
    {
        $this->assertTrue($this->provider->openid());
        $this->assertEquals('http://provider.example.com', $this->provider->issuer());
        $this->assertEquals('bar', $this->provider->metadata('foo'));
        $this->assertTrue($this->provider->supportsEndpoint('authorization'));
        $this->assertFalse($this->provider->supportsEndpoint('not_found'));
        $this->assertEquals('http://provider.example.com/authorize?foo=bar', $this->provider->uri('authorization', ['foo' => 'bar']));
    }

    /**
     *
     */
    public function test_keySet()
    {
        $this->httpClient->addResponse(new Response(200, [], json_encode($keys = new JWKSet([JWKFactory::createFromSecret('secret')]))));
        $this->assertEquals($keys, $this->provider->keySet());
        $this->assertCount(2, $this->httpClient->getRequests());
    }

    /**
     *
     */
    public function test_client()
    {
        $this->assertInstanceOf(Client::class, $this->provider->client(new ClientConfig('client_id')));
    }
}
