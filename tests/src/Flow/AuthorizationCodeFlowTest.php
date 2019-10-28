<?php

namespace Parroauth2\Client\Flow;

use BadMethodCallException;
use InvalidArgumentException;
use Parroauth2\Client\Client;
use Parroauth2\Client\ClientConfig;
use Parroauth2\Client\Exception\InvalidScopeException;
use Parroauth2\Client\Tests\FunctionalTestCase;

/**
 * Class AuthorizationCodeFlowTest
 */
class AuthorizationCodeFlowTest extends FunctionalTestCase
{
    /**
     * @var Client
     */
    private $client;

    /**
     * @var AuthorizationCodeFlow
     */
    private $flow;

    protected function setUp(): void
    {
        parent::setUp();

        $this->client = $this->client(
            (new ClientConfig('test'))
                ->setSecret('my-secret')
                ->setScopes(['email', 'name'])
                ->enableOpenId(false)
        );
        $this->flow = new AuthorizationCodeFlow($this->client);
        $this->dataSet
            ->pushClient('test', 'my-secret', 'http://client.example.com')
            ->pushScopes(['email', 'name'])
        ;
    }

    /**
     *
     */
    public function test_authorizationUri()
    {
        $uri = $this->flow->authorizationUri('http://client.example.com/connect');

        $this->assertStringStartsWith('http://localhost:5000/authorize', $uri);
        $this->assertContains('client_id=test', $uri);
        $this->assertContains('response_type=code', $uri);
        $this->assertContains('scope=email+name', $uri);
        $this->assertContains('redirect_uri=http%3A%2F%2Fclient.example.com%2Fconnect', $uri);
        $this->assertTrue($this->session->has('authorization'));
        $this->assertContains('state='.$this->session->retrieve('authorization')['state'], $uri);
    }

    /**
     *
     */
    public function test_authorizationUri_response()
    {
        $response = $this->httpClient->get($this->flow->authorizationUri('http://client.example.com'));

        $this->assertEquals(302, $response->getStatusCode());
        $location = $response->getHeaderLine('Location');

        $this->assertStringStartsWith('http://client.example.com', $location);
        parse_str(explode('?', $location)[1], $parameters);

        $this->assertArrayHasKey('code', $parameters);
        $this->assertSame($this->session->retrieve('authorization')['state'], $parameters['state']);
    }

    /**
     *
     */
    public function test_handleAuthorizationResponse_functional()
    {
        $location = $this->httpClient->get($this->flow->authorizationUri('http://client.example.com'))->getHeaderLine('Location');
        parse_str(explode('?', $location)[1], $parameters);

        $tokens = $this->flow->handleAuthorizationResponse($parameters);

        $this->assertNotEmpty($tokens->accessToken());
        $this->assertNotEmpty($tokens->refreshToken());
        $this->assertEquals('bearer', $tokens->type());
        $this->assertEquals(['email', 'name'], $tokens->scopes());
        $this->assertFalse($this->session->has('authorization'));
    }

    /**
     *
     */
    public function test_handleAuthorizationResponse_without_redirect_uri_functional()
    {
        $location = $this->httpClient->get($this->flow->authorizationUri())->getHeaderLine('Location');
        parse_str(explode('?', $location)[1], $parameters);

        $tokens = $this->flow->handleAuthorizationResponse($parameters);

        $this->assertNotEmpty($tokens->accessToken());
        $this->assertNotEmpty($tokens->refreshToken());
        $this->assertEquals('bearer', $tokens->type());
        $this->assertEquals(['email', 'name'], $tokens->scopes());
        $this->assertFalse($this->session->has('authorization'));
    }

    /**
     *
     */
    public function test_handleAuthorizationResponse_flow_not_started()
    {
        $this->expectException(BadMethodCallException::class);
        $this->expectExceptionMessage('The authorization flow is not started');

        $this->flow->handleAuthorizationResponse([]);
    }

    /**
     *
     */
    public function test_handleAuthorizationResponse_invalid_state()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid state');

        $this->flow->authorizationUri('http://client.example.com');

        $this->flow->handleAuthorizationResponse(['state' => 'invalid']);
    }

    /**
     *
     */
    public function test_handleAuthorizationResponse_missing_state()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid state');

        $this->flow->authorizationUri('http://client.example.com');

        $this->flow->handleAuthorizationResponse([]);
    }

    /**
     *
     */
    public function test_handleAuthorizationResponse_error_response_functional()
    {
        $this->expectException(InvalidScopeException::class);
        $this->expectExceptionMessage('An unsupported scope was requested');

        $this->client->clientConfig()->setScopes(['invalid']);

        $location = $this->httpClient->get($this->flow->authorizationUri('http://client.example.com'))->getHeaderLine('Location');
        parse_str(explode('?', $location)[1], $parameters);

        $this->flow->handleAuthorizationResponse($parameters);
    }
}
