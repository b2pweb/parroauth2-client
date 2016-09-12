<?php

namespace Parroauth2\Client;

require_once __DIR__ . '/_files/TestableClientAdapter.php';

use Bdf\Config\Config;
use Bdf\PHPUnit\TestCase;
use DateTime;
use Kangaroo\Client as KangarooClient;
use Kangaroo\ClientAdapter\TestableClientAdapter;
use Kangaroo\Response;
use Parroauth2\Client\Client as ParroauthClient;
use Parroauth2\Client\Exception\InternalErrorException;
use ReflectionClass;

/**
 * Class ClientTest
 * 
 * @package OAuth
 *
 * @group OAuth
 * @group OAuth/Client
 */
class ClientTest extends TestCase
{
    /**
     * @var TestableClientAdapter
     */
    protected $adapter;

    /**
     * @var ParroauthClient
     */
    protected $client;

    /**
     *
     */
    public function setUp()
    {
        $this->adapter = new TestableClientAdapter();

        $this->client = new ParroauthClient(
            new KangarooClient('http://localhost', $this->adapter),
            new Config([
                'path'         => '/oauth',
                'clientId'     => 'clientId',
                'clientSecret' => 'clientSecret',
            ])
        );
    }

    /**
     *
     */
    public function test_token_throws_connection_exception_if_credentials_are_invalid()
    {
        $this->setExpectedException('Parroauth2\Client\Exception\ConnectionException', 'Invalid credentials');

        $this->adapter->setResponse(
            (new Response())
                ->setStatusCode(400)
                ->setBody((object)['error' => 'invalid_grant'])
        );

        $this->client->token('invalid', 'credentials');
    }

    /**
     *
     */
    public function test_token_throws_internal_exception_if_an_error_occurs()
    {
        $this->setExpectedException('Parroauth2\Client\Exception\InternalErrorException');

        $this->adapter->setResponse((new Response())->setStatusCode(401));

        $this->client->token('invalid', 'credentials');
    }

    /**
     *
     */
    public function test_token_creates_token_properly()
    {
        $tokenValidity = 3600;
        $expectedToken = new Token('access_token', (new DateTime())->setTimestamp(time() + ($tokenValidity * 0.9)), 'refresh_token');

        $this->adapter->setResponse(
            (new Response())
                ->setStatusCode(200)
                ->setBody((object)[
                    'access_token'  => $expectedToken->getAccess(),
                    'expires_in'    => $tokenValidity,
                    'refresh_token' => $expectedToken->getRefresh(),
                ])
        );

        $token = $this->client->token('valid', 'credentials');

        $this->assertEquals($expectedToken->getAccess(), $token->getAccess(), 'Error on access token');
        $this->assertEquals($expectedToken->getValidityEndpoint(), $token->getValidityEndpoint(), 'Error on token validity endpoint', 1);
        $this->assertEquals($expectedToken->getRefresh(), $token->getRefresh(), 'Error on refresh token');
    }

    /**
     *
     */
    public function test_refresh_throws_invalid_token_if_an_error_occurs()
    {
        $this->setExpectedException('Parroauth2\Client\Exception\ConnectionException', 'Invalid token');

        $this->adapter->setResponse(
            (new Response())
                ->setStatusCode(400)
                ->setBody((object)['error' => 'invalid_grant'])
        );

        $this->client->refresh('access_token');
    }

    /**
     *
     */
    public function test_refresh_throws_internal_exception_if_an_error_occurs()
    {
        $this->setExpectedException('Parroauth2\Client\Exception\InternalErrorException');

        $this->adapter->setResponse((new Response())->setStatusCode(401));

        $this->client->refresh('refresh_token');
    }

    /**
     *
     */
    public function test_refresh_renew_token_properly()
    {
        $tokenValidity = 3600;
        $expectedToken = new Token('updated_access_token', (new DateTime())->setTimestamp(time() + ($tokenValidity * 0.9)), 'updated_refresh_token');

        $this->adapter->setResponse(
            (new Response())
                ->setStatusCode(200)
                ->setBody((object)[
                    'access_token'  => $expectedToken->getAccess(),
                    'expires_in'    => $tokenValidity,
                    'refresh_token' => $expectedToken->getRefresh(),
                ])
        );

        $token = $this->client->refresh(new Token('access_token', new DateTime(), 'refresh_token'));

        $this->assertEquals($expectedToken->getAccess(), $token->getAccess(), 'Error on access token');
        $this->assertEquals($expectedToken->getValidityEndpoint(), $token->getValidityEndpoint(), 'Error on token validity endpoint', 1);
        $this->assertEquals($expectedToken->getRefresh(), $token->getRefresh(), 'Error on refresh token');
    }

    /**
     *
     */
    public function test_userinfo_throws_internal_exception_if_an_error_occurs()
    {
        $this->setExpectedException('Parroauth2\Client\Exception\InternalErrorException');

        $this->adapter->setResponse((new Response())->setStatusCode(400));

        $this->client->userinfo('access_token');
    }

    /**
     *
     */
    public function test_userinfo_returns_data_properly()
    {
        $expectedUserinfo = [
            'id'   => 123,
            'name' => 'Phpunit Instance',
            'role' => 'tester',
        ];

        $this->adapter->setResponse(
            (new Response())
                ->setStatusCode(200)
                ->setBody((object)$expectedUserinfo)
        );

        $userinfo = $this->client->userinfo('access_token');

        $this->assertEquals($expectedUserinfo, $userinfo);
    }

    /**
     *
     */
    public function test_introspect_throws_internal_exception_if_an_error_occurs()
    {
        $this->setExpectedException('Parroauth2\Client\Exception\InternalErrorException');

        $this->adapter->setResponse((new Response())->setStatusCode(401));

        $this->client->introspect('access_token');
    }

    /**
     *
     */
    public function test_introspect_returns_data_properly()
    {
        $expectedIntrospection = [
            'id'   => 123,
            'name' => 'Phpunit Instance',
            'role' => 'tester',
        ];

        $this->adapter->setResponse(
            (new Response())
                ->setStatusCode(200)
                ->setBody((object)$expectedIntrospection)
        );

        $introspection = $this->client->introspect('access_token');

        $this->assertEquals($expectedIntrospection, $introspection);
    }

    /**
     *
     */
    public function test_internalError_generates_exception_from_valid_minimal_rfc_error()
    {
        $response = (new Response())
            ->setStatusCode(400)
            ->setBody((object)['error' => 'invalid_request'])
        ;

        $messageData = [
            'Configuration error',
            'Status code: ' . $response->getStatusCode(),
            'Error: ' . $response->getBody()->error,
        ];

        $expectedException = new InternalErrorException(implode(PHP_EOL, $messageData), 500);

        $class = new ReflectionClass('Parroauth2\Client\Client');
        $method = $class->getMethod('internalError');
        $method->setAccessible(true);

        $this->assertEquals($expectedException, $method->invokeArgs($this->client, [$response]));
    }

    /**
     *
     */
    public function test_internalError_generates_exception_from_valid_rfc_error()
    {
        $response = (new Response())
            ->setStatusCode(400)
            ->setBody((object)[
                'error' => 'invalid_request',
                'error_description' => 'Unable to find token or client not authenticated.',
                'error_uri' => 'http://localhost/error',
            ])
        ;

        $messageData = [
            'Configuration error',
            'Status code: ' . $response->getStatusCode(),
            'Error: ' . $response->getBody()->error,
            'Error description: ' . $response->getBody()->error_description,
            'Error URI: ' . $response->getBody()->error_uri,
        ];

        $expectedException = new InternalErrorException(implode(PHP_EOL, $messageData), 500);

        $class = new ReflectionClass('Parroauth2\Client\Client');
        $method = $class->getMethod('internalError');
        $method->setAccessible(true);

        $this->assertEquals($expectedException, $method->invokeArgs($this->client, [$response]));
    }

    /**
     *
     */
    public function test_internalError_generates_exception_from_body_as_string()
    {
        $response = (new Response())
            ->setStatusCode(404)
            ->setBody('Page not found')
        ;

        $messageData = [
            'Configuration error',
            'Status code: ' . $response->getStatusCode(),
            'Error: ' . $response->getBody(),
        ];

        $expectedException = new InternalErrorException(implode(PHP_EOL, $messageData), 500);

        $class = new ReflectionClass('Parroauth2\Client\Client');
        $method = $class->getMethod('internalError');
        $method->setAccessible(true);

        $this->assertEquals($expectedException, $method->invokeArgs($this->client, [$response]));
    }
}