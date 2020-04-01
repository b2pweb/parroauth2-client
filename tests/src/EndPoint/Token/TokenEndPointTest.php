<?php

namespace Parroauth2\Client\EndPoint\Token;

use Parroauth2\Client\Client;
use Parroauth2\Client\ClientConfig;
use Parroauth2\Client\EndPoint\EndPointTransformerInterface;
use Parroauth2\Client\Tests\FunctionalTestCase;

/**
 * Class TokenEndPointTest
 */
class TokenEndPointTest extends FunctionalTestCase
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

        $this->client = $this->client(
            (new ClientConfig('test'))
                ->setSecret('my-secret')
                ->setScopes(['email', 'name'])
                ->enableOpenId(false)
        );
        $this->endPoint = new TokenEndPoint($this->client);
        $this->dataSet
            ->pushClient('test', 'my-secret', 'http://client.example.com')
            ->pushScopes(['email', 'name'])
        ;
    }

    /**
     *
     */
    public function test_name()
    {
        $this->assertEquals('token', $this->endPoint->name());
    }

    /**
     *
     */
    public function test_parameters()
    {
        $this->assertEmpty($this->endPoint->parameters());

        $endPoint = $this->endPoint->set('foo', 'bar');
        $this->assertNotSame($endPoint, $this->endPoint);
        $this->assertArrayNotHasKey('foo', $this->endPoint->parameters());
        $this->assertEquals('bar', $endPoint->get('foo'));
        $this->assertEquals(['foo' => 'bar'], $endPoint->parameters());
    }

    /**
     *
     */
    public function test_apply()
    {
        $ret = $this->createMock(TokenEndPoint::class);
        $transformer = $this->createMock(EndPointTransformerInterface::class);
        $transformer->expects($this->once())->method('onToken')->with($this->endPoint)->willReturn($ret);

        $this->assertSame($ret, $this->endPoint->apply($transformer));
    }

    /**
     *
     */
    public function test_code_functional()
    {
        $response = $this->endPoint->code($this->code())->call();

        $this->assertInstanceOf(TokenResponse::class, $response);
        $this->assertEquals('bearer', $response->type());
        $this->assertEquals(new \DateTime('+1 hour'), $response->expiresAt(), '', 10);
        $this->assertNotEmpty($response->accessToken());
        $this->assertNotEmpty($response->refreshToken());
    }

    /**
     *
     */
    public function test_code_with_redirect_uri_functional()
    {
        $response = $this->endPoint->code($this->code('http://client.example.com'), 'http://client.example.com')->call();

        $this->assertInstanceOf(TokenResponse::class, $response);
        $this->assertEquals('bearer', $response->type());
        $this->assertEquals(new \DateTime('+1 hour'), $response->expiresAt(), '', 10);
        $this->assertNotEmpty($response->accessToken());
        $this->assertNotEmpty($response->refreshToken());
    }

    /**
     *
     */
    public function test_password_functional()
    {
        $this->dataSet->pushUser('bob', 'my-password');

        $response = $this->endPoint->password('bob', 'my-password')->call();

        $this->assertInstanceOf(TokenResponse::class, $response);
        $this->assertEquals('bearer', $response->type());
        $this->assertEquals(new \DateTime('+1 hour'), $response->expiresAt(), '', 10);
        $this->assertNotEmpty($response->accessToken());
        $this->assertNotEmpty($response->refreshToken());
    }

    /**
     *
     */
    public function test_password_with_scopes_functional()
    {
        $this->dataSet->pushUser('bob', 'my-password');

        $response = $this->endPoint->password('bob', 'my-password', ['email', 'name'])->call();

        $this->assertInstanceOf(TokenResponse::class, $response);
        $this->assertEquals('bearer', $response->type());
        $this->assertEquals(new \DateTime('+1 hour'), $response->expiresAt(), '', 10);
        $this->assertNotEmpty($response->accessToken());
        $this->assertNotEmpty($response->refreshToken());
        $this->assertEquals(['email', 'name'], $response->scopes());
    }

    /**
     *
     */
    public function test_refresh_functional()
    {
        $token = $this->endPoint->code($this->code('http://client.example.com'))->call()->refreshToken();

        $response = $this->endPoint->refresh($token)->call();

        $this->assertInstanceOf(TokenResponse::class, $response);
        $this->assertEquals('bearer', $response->type());
        $this->assertEquals(new \DateTime('+1 hour'), $response->expiresAt(), '', 10);
        $this->assertNotEmpty($response->accessToken());
        $this->assertNotEmpty($response->refreshToken());
    }

    /**
     *
     */
    public function test_refresh_with_scopes_functional()
    {
        $token = $this->endPoint->code($this->code('http://client.example.com'))->call()->refreshToken();

        $response = $this->endPoint->refresh($token, ['email', 'name'])->call();

        $this->assertInstanceOf(TokenResponse::class, $response);
        $this->assertEquals('bearer', $response->type());
        $this->assertEquals(new \DateTime('+1 hour'), $response->expiresAt(), '', 10);
        $this->assertEquals(['email', 'name'], $response->scopes());
        $this->assertNotEmpty($response->accessToken());
        $this->assertNotEmpty($response->refreshToken());
    }

    private function code(?string $redirectUri = null): string
    {
        $location = $this->httpClient->get($this->client->endPoints()->authorization($redirectUri)->code()->uri())->getHeaderLine('Location');
        parse_str(explode('?', $location)[1], $parameters);

        return $parameters['code'];
    }
}
