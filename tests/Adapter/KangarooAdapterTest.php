<?php

namespace Parroauth2\Client\Adapter;

require_once __DIR__ . '/_files/TestableHttpClientAdapter.php';

use Bdf\PHPUnit\TestCase;
use DateTime;
use Kangaroo\Client as KangarooClient;
use Kangaroo\ClientAdapter\TestableHttpClientAdapter;
use Kangaroo\Response;
use Parroauth2\Client\Exception\InternalErrorException;
use Parroauth2\Client\Grant;
use ReflectionClass;

/**
 * Class KangarooAdapterTest
 * 
 * @package Parroauth2\Client\Adapter
 *
 * @group Parroauth2
 * @group Parroauth2/Client
 * @group Parroauth2/Client/Adapter
 * @group Parroauth2/Client/Adapter/KangarooAdapterTest
 */
class KangarooAdapterTest extends TestCase
{
    /**
     * @var TestableHttpClientAdapter
     */
    protected $httpAdapter;

    /**
     * @var KangarooAdapter
     */
    protected $adapter;

    /**
     *
     */
    public function setUp()
    {
        $this->httpAdapter = new TestableHttpClientAdapter();

        $this->adapter = new KangarooAdapter(
            new KangarooClient('http://localhost', $this->httpAdapter),
            [
                'path'         => '/oauth',
                'clientId'     => 'clientId',
                'clientSecret' => 'clientSecret',
            ]
        );
    }

    /**
     *
     */
    public function test_token_throws_connection_exception_if_credentials_are_invalid()
    {
        $this->setExpectedException('Parroauth2\Client\Exception\ConnectionException', 'Invalid credentials');

        $this->httpAdapter->setResponse(
            (new Response())
                ->setStatusCode(400)
                ->setBody((object)['error' => 'invalid_grant'])
        );

        $this->adapter->token('invalid', 'credentials');
    }

    /**
     *
     */
    public function test_token_throws_internal_exception_if_an_error_occurs()
    {
        $this->setExpectedException('Parroauth2\Client\Exception\InternalErrorException');

        $this->httpAdapter->setResponse((new Response())->setStatusCode(401));

        $this->adapter->token('invalid', 'credentials');
    }

    /**
     *
     */
    public function test_token_creates_token_properly()
    {
        $tokenValidity = 3600;
        $expectedGrant = new Grant('access_token', (new DateTime())->setTimestamp(time() + ($tokenValidity * 0.9)), 'refresh_token');

        $this->httpAdapter->setResponse(
            (new Response())
                ->setStatusCode(200)
                ->setBody((object)[
                    'access_token'  => $expectedGrant->getAccess(),
                    'expires_in'    => $tokenValidity,
                    'refresh_token' => $expectedGrant->getRefresh(),
                ])
        );

        $token = $this->adapter->token('valid', 'credentials');

        $this->assertEquals($expectedGrant->getAccess(), $token->getAccess(), 'Error on access token');
        $this->assertEquals($expectedGrant->getValidityEndpoint(), $token->getValidityEndpoint(), 'Error on token validity endpoint', 1);
        $this->assertEquals($expectedGrant->getRefresh(), $token->getRefresh(), 'Error on refresh token');
    }

    /**
     *
     */
    public function test_refresh_throws_invalid_token_if_an_error_occurs()
    {
        $this->setExpectedException('Parroauth2\Client\Exception\ConnectionException', 'Invalid token');

        $this->httpAdapter->setResponse(
            (new Response())
                ->setStatusCode(400)
                ->setBody((object)['error' => 'invalid_grant'])
        );

        $this->adapter->refresh('access_token');
    }

    /**
     *
     */
    public function test_refresh_throws_internal_exception_if_an_error_occurs()
    {
        $this->setExpectedException('Parroauth2\Client\Exception\InternalErrorException');

        $this->httpAdapter->setResponse((new Response())->setStatusCode(401));

        $this->adapter->refresh('refresh_token');
    }

    /**
     *
     */
    public function test_refresh_renew_token_properly()
    {
        $tokenValidity = 3600;
        $expectedGrant = new Grant('updated_access_token', (new DateTime())->setTimestamp(time() + ($tokenValidity * 0.9)), 'updated_refresh_token');

        $this->httpAdapter->setResponse(
            (new Response())
                ->setStatusCode(200)
                ->setBody((object)[
                    'access_token'  => $expectedGrant->getAccess(),
                    'expires_in'    => $tokenValidity,
                    'refresh_token' => $expectedGrant->getRefresh(),
                ])
        );

        $token = $this->adapter->refresh(new Grant('access_token', new DateTime(), 'refresh_token'));

        $this->assertEquals($expectedGrant->getAccess(), $token->getAccess(), 'Error on access token');
        $this->assertEquals($expectedGrant->getValidityEndpoint(), $token->getValidityEndpoint(), 'Error on token validity endpoint', 1);
        $this->assertEquals($expectedGrant->getRefresh(), $token->getRefresh(), 'Error on refresh token');
    }

    /**
     *
     */
    public function test_userinfo_throws_internal_exception_if_an_error_occurs()
    {
        $this->setExpectedException('Parroauth2\Client\Exception\InternalErrorException');

        $this->httpAdapter->setResponse((new Response())->setStatusCode(400));

        $this->adapter->userinfo('access_token');
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

        $this->httpAdapter->setResponse(
            (new Response())
                ->setStatusCode(200)
                ->setBody((object)$expectedUserinfo)
        );

        $userinfo = $this->adapter->userinfo('access_token');

        $this->assertEquals($expectedUserinfo, $userinfo);
    }

    /**
     *
     */
    public function test_introspect_throws_internal_exception_if_an_error_occurs()
    {
        $this->setExpectedException('Parroauth2\Client\Exception\InternalErrorException');

        $this->httpAdapter->setResponse((new Response())->setStatusCode(401));

        $this->adapter->introspect('access_token');
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

        $this->httpAdapter->setResponse(
            (new Response())
                ->setStatusCode(200)
                ->setBody((object)$expectedIntrospection)
        );

        $introspection = $this->adapter->introspect('access_token');

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

        $class = new ReflectionClass('Parroauth2\Client\Adapter\KangarooAdapter');
        $method = $class->getMethod('internalError');
        $method->setAccessible(true);

        $this->assertEquals($expectedException, $method->invokeArgs($this->adapter, [$response]));
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

        $class = new ReflectionClass('Parroauth2\Client\Adapter\KangarooAdapter');
        $method = $class->getMethod('internalError');
        $method->setAccessible(true);

        $this->assertEquals($expectedException, $method->invokeArgs($this->adapter, [$response]));
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

        $class = new ReflectionClass('Parroauth2\Client\Adapter\KangarooAdapter');
        $method = $class->getMethod('internalError');
        $method->setAccessible(true);

        $this->assertEquals($expectedException, $method->invokeArgs($this->adapter, [$response]));
    }
}