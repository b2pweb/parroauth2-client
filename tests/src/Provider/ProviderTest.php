<?php

namespace Parroauth2\Client\Provider;

use Cache\Adapter\PHPArray\ArrayCachePool;
use Http\Discovery\Psr17FactoryDiscovery;
use Nyholm\Psr7\Response;
use Http\Discovery\MessageFactoryDiscovery;
use Parroauth2\Client\Client;
use Parroauth2\Client\ClientConfig;
use Parroauth2\Client\Exception\Parroauth2Exception;
use Parroauth2\Client\Exception\UnsupportedServerOperation;
use Parroauth2\Client\Factory\BaseClientFactory;
use Parroauth2\Client\Tests\UnitTestCase;

/**
 * Class ProviderTest
 */
class ProviderTest extends UnitTestCase
{
    /**
     * @var Provider
     */
    private $provider;

    /**
     * @var ProviderConfig
     */
    private $config;

    protected function setUp(): void
    {
        parent::setUp();

        $this->provider = new Provider(
            new BaseClientFactory($this->session),
            $this->httpClient,
            Psr17FactoryDiscovery::findRequestFactory(),
            Psr17FactoryDiscovery::findStreamFactory(),
            $this->config = new ProviderConfig(
                'http://provider.example.com',
                [
                    'issuer' => 'http://provider.example.com',
                    'authorization_endpoint' => 'http://provider.example.com/authorize',
                    'with_query_endpoint' => 'http://provider.example.com?foo=bar',
                    'foo' => 'bar',
                ],
                true
            )
        );
    }

    /**
     *
     */
    public function test_getters()
    {
        $this->assertEquals('http://provider.example.com', $this->provider->issuer());
        $this->assertTrue($this->provider->openid());
        $this->assertEquals('bar', $this->provider->metadata('foo'));
        $this->assertEquals(404, $this->provider->metadata('not_found', 404));
    }

    /**
     *
     */
    public function test_supportsEndpoint()
    {
        $this->assertTrue($this->provider->supportsEndpoint('authorization'));
        $this->assertFalse($this->provider->supportsEndpoint('not_found'));
    }

    /**
     *
     */
    public function test_uri_endpoint_not_supported()
    {
        $this->expectException(UnsupportedServerOperation::class);
        $this->expectExceptionMessage('The endpoint "not_found" is not supported by the authorization provider');

        $this->provider->uri('not_found');
    }

    /**
     *
     */
    public function test_uri()
    {
        $this->assertEquals('http://provider.example.com/authorize', $this->provider->uri('authorization'));
        $this->assertEquals('http://provider.example.com/authorize?foo=bar', $this->provider->uri('authorization', ['foo' => 'bar']));
        $this->assertEquals('http://provider.example.com?foo=bar&aaa=bbb', $this->provider->uri('with_query', ['aaa' => 'bbb']));
    }

    /**
     *
     */
    public function test_request()
    {
        $request = $this->provider->request('POST', 'authorization', ['foo' => 'bar'], ['aaa' => 'bbb']);

        $this->assertEquals('POST', $request->getMethod());
        $this->assertEquals('http://provider.example.com/authorize?foo=bar', (string) $request->getUri());
        $this->assertEquals('aaa=bbb', (string) $request->getBody());
    }

    /**
     *
     */
    public function test_request_with_default_headers()
    {
        $this->provider = new Provider(
            new BaseClientFactory($this->session),
            $this->httpClient,
            Psr17FactoryDiscovery::findRequestFactory(),
            Psr17FactoryDiscovery::findStreamFactory(),
            $this->config = new ProviderConfig(
                'http://provider.example.com',
                [
                    'issuer' => 'http://provider.example.com',
                    'authorization_endpoint' => 'http://provider.example.com/authorize',
                    'with_query_endpoint' => 'http://provider.example.com?foo=bar',
                    'foo' => 'bar',
                    'default_headers' => [
                        'Content-Type' => 'application/x-www-form-urlencoded',
                        'X-Foo' => 'BAR',
                    ],
                ],
                true
            )
        );

        $request = $this->provider->request('POST', 'authorization', ['foo' => 'bar'], ['aaa' => 'bbb']);

        $this->assertEquals('POST', $request->getMethod());
        $this->assertEquals('http://provider.example.com/authorize?foo=bar', (string) $request->getUri());
        $this->assertEquals('aaa=bbb', (string) $request->getBody());
        $this->assertEquals('application/x-www-form-urlencoded', $request->getHeaderLine('Content-Type'));
        $this->assertEquals('BAR', $request->getHeaderLine('X-Foo'));
    }

    /**
     *
     */
    public function test_send_request_success()
    {
        $request = $this->provider->request('GET', 'authorization');
        $response = new Response();

        $this->httpClient->addResponse($response);

        $this->assertSame($response, $this->provider->sendRequest($request));
        $this->assertSame([$request], $this->httpClient->getRequests());
    }

    /**
     *
     */
    public function test_send_request_error_not_json()
    {
        $this->expectException(Parroauth2Exception::class);
        $this->expectExceptionMessage("An error has occurred:\nMy error");

        $request = $this->provider->request('GET', 'authorization');
        $response = new Response(400, [], 'My error');

        $this->httpClient->addResponse($response);

        $this->provider->sendRequest($request);
    }

    /**
     *
     */
    public function test_send_request_error_json_string()
    {
        $this->expectException(Parroauth2Exception::class);
        $this->expectExceptionMessage('My error');

        $request = $this->provider->request('GET', 'authorization');
        $response = new Response(400, [], '"My error"');

        $this->httpClient->addResponse($response);

        $this->provider->sendRequest($request);
    }

    /**
     *
     */
    public function test_send_request_error_json_object()
    {
        $this->expectException(Parroauth2Exception::class);
        $this->expectExceptionMessage('my description');

        $request = $this->provider->request('GET', 'authorization');
        $response = new Response(400, [], json_encode(['error' => 'my error', 'error_description' => 'my description', 'hint' => 'my hint']));

        $this->httpClient->addResponse($response);

        $this->provider->sendRequest($request);
    }

    /**
     *
     */
    public function test_send_request_error_json_object_invalid()
    {
        $this->expectException(Parroauth2Exception::class);
        $this->expectExceptionMessage('An error has occurred');

        $request = $this->provider->request('GET', 'authorization');
        $response = new Response(400, [], json_encode(['error' => ['invalid']]));

        $this->httpClient->addResponse($response);

        $this->provider->sendRequest($request);
    }

    /**
     *
     */
    public function test_send_request_error_json_invalid()
    {
        $this->expectException(Parroauth2Exception::class);
        $this->expectExceptionMessage('An error has occurred');

        $request = $this->provider->request('GET', 'authorization');
        $response = new Response(400, [], '123');

        $this->httpClient->addResponse($response);

        $this->provider->sendRequest($request);
    }

    /**
     *
     */
    public function test_client()
    {
        $client = $this->provider->client((new ClientConfig('test')));

        $this->assertInstanceOf(Client::class, $client);
        $this->assertEquals('test', $client->clientId());
        $this->assertSame($this->provider, $client->provider());
    }

    /**
     *
     */
    public function test_keySet_functional()
    {
        $provider = (new ProviderLoader(new BaseClientFactory($this->session)))->discover('http://localhost:5000');
        $keySet = $provider->keySet();

        $this->assertCount(1, $keySet);
        $this->assertSame($keySet, $provider->keySet());
    }

    /**
     *
     */
    public function test_keySet_should_cache_the_keySet()
    {
        $json = '{"keys":[{"kty":"RSA","n":"uQZWJXZL8gxRQ70j8PO0fixNjdyuDbO_E6b2shcfXMFo46ROTnY9tx2X6MuHlV3VyF3xKG9acGnNNgfjTYcvLFMAF641UmlS5DWsB6BbN-89pA-kYQbjYL2MIAZjrJMRw_xsOMbkhgGaYhw4OfV8RxAQnkkQhLU5zJVCyHt0WTk","e":"AQAB","use":"sig","alg":"RS256"}]}';
        $this->config['jwks_uri'] = 'http://op.example.com/jwks.json';

        $this->config->setCache($cache = new ArrayCachePool());
        $this->httpClient->addResponse(new Response(200, ['content-type' => 'application/json'], $json));

        $this->assertCount(1, $this->provider->keySet());
        $this->assertEquals($this->provider->keySet(), $cache->get(ProviderConfigPool::urlToKey('http://provider.example.com'))['jwks']);
    }
}
