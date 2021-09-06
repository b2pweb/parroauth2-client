<?php

namespace Parroauth2\Client\Provider;

use Cache\Adapter\PHPArray\ArrayCachePool;
use Nyholm\Psr7\Response;
use Parroauth2\Client\Factory\BaseClientFactory;
use Parroauth2\Client\Tests\UnitTestCase;

/**
 * Class ProviderLoaderTest
 */
class ProviderLoaderTest extends UnitTestCase
{
    /**
     * @var ProviderLoader
     */
    private $loader;

    protected function setUp(): void
    {
        parent::setUp();

        $this->loader = new ProviderLoader(new BaseClientFactory($this->session), $this->httpClient);
    }

    /**
     *
     */
    public function test_discover_openid_functional()
    {
        $loader = new ProviderLoader(new BaseClientFactory($this->session));

        $provider = $loader->discover('http://localhost:5000');

        $this->assertInstanceOf(Provider::class, $provider);
        $this->assertTrue($provider->openid());
        $this->assertEquals('http://localhost:5000', $provider->issuer());
        $this->assertEquals('http://localhost:5000/authorize', $provider->metadata('authorization_endpoint'));
    }

    /**
     *
     */
    public function test_discover_openid_unit()
    {
        $this->httpClient->addResponse(new Response(200, [], json_encode([
            'issuer' => 'http://provider.example.com',
            'authorization_endpoint' => 'http://provider.example.com/authorize'
        ])));

        $provider = $this->loader->discover('http://provider.example.com');

        $this->assertTrue($provider->openid());
        $this->assertEquals('http://provider.example.com', $provider->issuer());
        $this->assertEquals('http://provider.example.com/authorize', $provider->metadata('authorization_endpoint'));

        $this->assertCount(1, $this->httpClient->getRequests());
        $this->assertEquals('http://provider.example.com/.well-known/openid-configuration', $this->httpClient->getLastRequest()->getUri());
    }

    /**
     *
     */
    public function test_discover_oauth2_unit()
    {
        $this->httpClient->addResponse(new Response(404));
        $this->httpClient->addResponse(new Response(200, [], json_encode([
            'issuer' => 'http://provider.example.com',
            'authorization_endpoint' => 'http://provider.example.com/authorize'
        ])));

        $provider = $this->loader->discover('http://provider.example.com');

        $this->assertFalse($provider->openid());
        $this->assertEquals('http://provider.example.com', $provider->issuer());
        $this->assertEquals('http://provider.example.com/authorize', $provider->metadata('authorization_endpoint'));

        $this->assertCount(2, $this->httpClient->getRequests());
        $this->assertEquals('http://provider.example.com/.well-known/openid-configuration', $this->httpClient->getRequests()[0]->getUri());
        $this->assertEquals('http://provider.example.com/.well-known/oauth-authorization-server', $this->httpClient->getLastRequest()->getUri());
    }

    /**
     *
     */
    public function test_discover_metadata_not_found()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Authorization provider discovery is not supported by the server');

        $this->httpClient->addResponse(new Response(404));
        $this->httpClient->addResponse(new Response(404));

        $this->loader->discover('http://provider.example.com');
    }

    /**
     *
     */
    public function test_discover_should_cache()
    {
        $this->loader = new ProviderLoader(new BaseClientFactory($this->session), $this->httpClient, null, null, $pool = new ProviderConfigPool($cache = new ArrayCachePool()));
        $this->httpClient->addResponse(new Response(200, [], json_encode([
            'issuer' => 'http://provider.example.com',
            'authorization_endpoint' => 'http://provider.example.com/authorize'
        ])));

        $provider = $this->loader->discover('http://provider.example.com');

        $this->assertTrue($provider->openid());
        $this->assertEquals('http://provider.example.com', $provider->issuer());
        $this->assertEquals('http://provider.example.com/authorize', $provider->metadata('authorization_endpoint'));

        $this->assertEquals('http://provider.example.com/.well-known/openid-configuration', $this->httpClient->getLastRequest()->getUri());

        $this->assertEquals($provider, $this->loader->discover('http://provider.example.com'));

        $this->assertCount(1, $this->httpClient->getRequests());
        $expectedConfig = new ProviderConfig('http://provider.example.com', [
            'issuer' => 'http://provider.example.com',
            'authorization_endpoint' => 'http://provider.example.com/authorize'
        ], true);
        $expectedConfig->setCache($cache);
        $this->assertEquals($expectedConfig, $pool->get('http://provider.example.com'));
    }

    /**
     *
     */
    public function test_create()
    {
        $provider = $this->loader->create([
            'issuer' => 'http://provider.example.com',
            'authorization_endpoint' => 'http://provider.example.com/authorize'
        ], true);

        $this->assertTrue($provider->openid());
        $this->assertEquals('http://provider.example.com', $provider->issuer());
        $this->assertEquals('http://provider.example.com/authorize', $provider->metadata('authorization_endpoint'));
    }

    /**
     *
     */
    public function test_builder()
    {
        $builder = $this->loader->builder('http://op.example.com');

        $this->assertInstanceOf(ProviderBuilder::class, $builder);

        $provider = $builder->authorizationEndPoint('/authorize')->openid()->create();

        $this->assertTrue($provider->openid());
        $this->assertEquals('http://op.example.com', $provider->issuer());
        $this->assertEquals('http://op.example.com/authorize', $provider->metadata('authorization_endpoint'));
    }

    /**
     *
     */
    public function test_lazy()
    {
        $this->httpClient->addResponse(new Response(200, [], json_encode([
            'issuer' => 'http://provider.example.com',
            'authorization_endpoint' => 'http://provider.example.com/authorize'
        ])));

        $provider = $this->loader->lazy('http://provider.example.com');
        $this->assertInstanceOf(ProxyProvider::class, $provider);

        $this->assertCount(0, $this->httpClient->getRequests());

        $this->assertTrue($provider->openid());
        $this->assertEquals('http://provider.example.com', $provider->issuer());
        $this->assertEquals('http://provider.example.com/authorize', $provider->metadata('authorization_endpoint'));

        $this->assertCount(1, $this->httpClient->getRequests());
        $this->assertEquals('http://provider.example.com/.well-known/openid-configuration', $this->httpClient->getLastRequest()->getUri());
    }
}
