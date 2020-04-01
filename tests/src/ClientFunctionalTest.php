<?php

namespace Parroauth2\Client;

use Jose\Component\Core\JWKSet;
use Parroauth2\Client\EndPoint\EndPoints;
use Parroauth2\Client\OpenID\EndPoint\Userinfo\UserinfoEndPoint;
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

    /**
     *
     */
    public function test_login()
    {
        $response = $this->client->login('bob', '$bob');

        $this->assertInstanceOf(Authorization::class, $response);
        $this->assertNotEmpty($response->accessToken());
        $this->assertNotEmpty($response->refreshToken());
        $this->assertEquals('bearer', $response->tokenType());
        $this->assertEquals(3600, $response->lifetime());
    }

    /**
     *
     */
    public function test_refresh()
    {
        $token = $this->client->login('bob', '$bob');

        $response = $this->client->refresh($token);

        $this->assertInstanceOf(Authorization::class, $response);
        $this->assertNotEmpty($response->accessToken());
        $this->assertNotEmpty($response->refreshToken());
        $this->assertEquals('bearer', $response->tokenType());
        $this->assertEquals(3600, $response->lifetime());
    }

    /**
     *
     */
    public function test_tokenFromAuthorizationCode()
    {
        $location = $this->httpClient->get($this->client->endPoints()->authorization()->code('http://client.example.com')->uri())->getHeaderLine('Location');
        parse_str(explode('?', $location)[1], $parameters);

        $response = $this->client->tokenFromAuthorizationCode($parameters['code'], 'http://client.example.com');

        $this->assertInstanceOf(Authorization::class, $response);
        $this->assertNotEmpty($response->accessToken());
        $this->assertEquals('bearer', $response->tokenType());
        $this->assertEquals(3600, $response->lifetime());
    }

    /**
     *
     */
    public function test_getAuthorizationUri()
    {
        $uri = $this->client->getAuthorizationUri('http://client.example.com');

        $this->assertStringStartsWith('http://localhost:5000/authorize?', $uri);
        $this->assertContains('response_type=code', $uri);
        $this->assertContains('client_id=test', $uri);
        $this->assertContains('redirect_uri='.urlencode('http://client.example.com'), $uri);
    }

    /**
     *
     */
    public function test_getAuthorizationUri_with_scopes()
    {
        $uri = $this->client->getAuthorizationUri('http://client.example.com', ['foo', 'bar']);

        $this->assertStringStartsWith('http://localhost:5000/authorize?', $uri);
        $this->assertContains('response_type=code', $uri);
        $this->assertContains('client_id=test', $uri);
        $this->assertContains('redirect_uri='.urlencode('http://client.example.com'), $uri);
        $this->assertContains('scope=foo+bar', $uri);
    }

    /**
     *
     */
    public function test_getAuthorizationUri_with_state()
    {
        $uri = $this->client->getAuthorizationUri('http://client.example.com', null, 'my_state');

        $this->assertStringStartsWith('http://localhost:5000/authorize?', $uri);
        $this->assertContains('response_type=code', $uri);
        $this->assertContains('client_id=test', $uri);
        $this->assertContains('redirect_uri='.urlencode('http://client.example.com'), $uri);
        $this->assertContains('state=my_state', $uri);
    }

    /**
     *
     */
    public function test_getAuthorizationUri_with_other_client_id()
    {
        $uri = $this->client->getAuthorizationUri('http://client.example.com', null, null, 'other_client');

        $this->assertStringStartsWith('http://localhost:5000/authorize?', $uri);
        $this->assertContains('response_type=code', $uri);
        $this->assertContains('client_id=other_client', $uri);
        $this->assertContains('redirect_uri='.urlencode('http://client.example.com'), $uri);
    }

    /**
     *
     */
    public function test_getAuthorizationUri_with_custom_parameter()
    {
        $uri = $this->client->getAuthorizationUri('http://client.example.com', null, null, null, ['foo' => 'bar']);

        $this->assertStringStartsWith('http://localhost:5000/authorize?', $uri);
        $this->assertContains('response_type=code', $uri);
        $this->assertContains('client_id=test', $uri);
        $this->assertContains('redirect_uri='.urlencode('http://client.example.com'), $uri);
        $this->assertContains('foo=bar', $uri);
    }

    /**
     *
     */
    public function test_introspect()
    {
        $token = $this->client->login('bob', '$bob');
        $introspect = $this->client->introspect($token);

        $this->assertTrue($introspect->isActive());
        $this->assertEquals('test', $introspect->clientId());
    }

    /**
     *
     */
    public function test_revoke()
    {
        $token = $this->client->login('bob', '$bob');
        $this->client->revoke($token);

        $this->assertFalse($this->client->introspect($token)->isActive());
    }

    /**
     *
     */
    public function test_userinfo()
    {
        $this->client->endPoints()->add(new UserinfoEndPoint($this->client));
        $token = $this->client->login('bob', '$bob', ['openid']);

        $response = $this->client->userinfo($token);

        $this->assertEquals('bob', $response->subject());
    }
}
