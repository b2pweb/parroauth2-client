<?php

namespace Parroauth2\Client\EndPoint\Introspection;

use GuzzleHttp\Psr7\Response;
use Parroauth2\Client\Client;
use Parroauth2\Client\ClientConfig;
use Parroauth2\Client\EndPoint\Token\TokenEndPoint;
use Parroauth2\Client\Tests\UnitTestCase;

/**
 * Class IntrospectionEndPointTest
 */
class IntrospectionEndPointTest extends UnitTestCase
{
    /**
     * @var Client
     */
    private $client;

    /**
     * @var TokenEndPoint
     */
    private $endPoint;

    protected function setUp(): void
    {
        parent::setUp();

        $this->client = $this->provider()->client(
            (new ClientConfig('test'))
                ->setSecret('my-secret')
                ->setScopes(['email', 'name'])
        );
        $this->endPoint = new IntrospectionEndPoint($this->client);
    }

    /**
     *
     */
    public function test_accessToken()
    {
        $this->httpClient->addResponse(new Response(200, [], json_encode(['active' => true, 'sub' => 123])));

        $response = $this->endPoint->accessToken('AT')->call();

        $this->assertInstanceOf(IntrospectionResponse::class, $response);
        $this->assertTrue($response->active());
        $this->assertEquals(123, $response->subject());

        $this->assertEquals('POST', $this->httpClient->getLastRequest()->getMethod());
        $this->assertEquals('http://op.example.com/introspection', (string) $this->httpClient->getLastRequest()->getUri());
        $this->assertEquals('token=AT&token_type_hint=access_token', (string) $this->httpClient->getLastRequest()->getBody());
        $this->assertEquals('Basic dGVzdDpteS1zZWNyZXQ=', $this->httpClient->getLastRequest()->getHeaderLine('Authorization'));
    }

    /**
     *
     */
    public function test_refreshToken()
    {
        $this->httpClient->addResponse(new Response(200, [], json_encode(['active' => true, 'sub' => 123])));

        $response = $this->endPoint->refreshToken('RT')->call();

        $this->assertInstanceOf(IntrospectionResponse::class, $response);
        $this->assertTrue($response->active());
        $this->assertEquals(123, $response->subject());

        $this->assertEquals('POST', $this->httpClient->getLastRequest()->getMethod());
        $this->assertEquals('http://op.example.com/introspection', (string) $this->httpClient->getLastRequest()->getUri());
        $this->assertEquals('token=RT&token_type_hint=refresh_token', (string) $this->httpClient->getLastRequest()->getBody());
        $this->assertEquals('Basic dGVzdDpteS1zZWNyZXQ=', $this->httpClient->getLastRequest()->getHeaderLine('Authorization'));
    }

    /**
     *
     */
    public function test_onResponse()
    {
        $this->httpClient->addResponse(new Response(200, [], json_encode(['active' => true, 'sub' => 123])));

        $response = $this->endPoint->accessToken('AT')
            ->onResponse(function ($response) use(&$listenerResponse) { $listenerResponse = $response; })
            ->call()
        ;

        $this->assertSame($response, $listenerResponse);
    }
}
