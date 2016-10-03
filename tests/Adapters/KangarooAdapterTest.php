<?php

namespace Parroauth2\Client\Tests\Adapters;

use Bdf\PHPUnit\TestCase;
use DateTime;
use Kangaroo\Client;
use Kangaroo\Request as KangarooRequest;
use Kangaroo\Response as KangarooResponse;
use Parroauth2\Client\Adapters\KangarooAdapter;
use Parroauth2\Client\ClientCredentials;
use Parroauth2\Client\Exception\InternalErrorException;
use Parroauth2\Client\Request;
use Parroauth2\Client\Response;
use Parroauth2\Client\Tests\Stubs\TestableHttpClientAdapter;
use ReflectionClass;

/**
 * Class KangarooAdapterTest
 *
 * @group Parroauth2
 * @group Parroauth2/Client
 * @group Parroauth2/Client/Adapters
 * @group Parroauth2/Client/Adapters/KangarooAdapter
 */
class KangarooAdapterTest extends TestCase
{
    /**
     * @var TestableHttpClientAdapter
     */
    protected $http;

    /**
     * @var string
     */
    protected $basePath;

    /**
     * @var KangarooAdapter
     */
    protected $adapter;

    /**
     *
     */
    public function setUp()
    {
        $this->http = new TestableHttpClientAdapter();
        $this->basePath = 'oauth2';
        $this->adapter = new KangarooAdapter((new Client('http://localhost', $this->http))->api($this->basePath));
    }

    /**
     *
     */
    public function test_token_throws_connection_exception_if_grant_type_is_invalid()
    {
        $this->setExpectedException('Parroauth2\Client\Exception\ConnectionException', 'Invalid credentials');

        $this->http->setResponse(
            (new KangarooResponse())
                ->setStatusCode(400)
                ->setBody((object)['error' => 'invalid_grant'])
        );

        $this->adapter->token(new Request());
    }

    /**
     *
     */
    public function test_token_throws_internal_exception_if_an_error_occurs()
    {
        $this->setExpectedException('Parroauth2\Client\Exception\InternalErrorException');

        $this->http->setResponse((new KangarooResponse())->setStatusCode(401));

        $this->adapter->token(new Request());
    }

    /**
     *
     */
    public function test_token_returns_authorization_data_properly()
    {
        $expectedResponse = new Response([
            'access_token'  => 'access_token',
            'expires_in'    => (new DateTime('tomorrow'))->getTimestamp(),
            'refresh_token' => 'refresh_token',
            'token_type'    => 'Bearer',
        ]);

        $this->http->setResponse(
            (new KangarooResponse())
                ->setStatusCode(200)
                ->setBody($expectedResponse->getBody())
        );

        $response = $this->adapter->token(new Request());

        $this->assertEquals($expectedResponse, $response);
    }

    /**
     *
     */
    public function test_token_sends_request_data_properly()
    {
        $this->http->setResponse(function (KangarooRequest $request) {
            return new KangarooResponse(
                [
                    'path'          => $request->getPath(),
                    'postFields'    => $request->getPostFields(),
                    'queries'       => $request->getQueries(),
                    'client_id'     => $request->getHeader('client_id'),
                    'client_secret' => $request->getHeader('client_secret'),
                ],
                200
            );
        });

        $request = new Request(['some' => 'parameter'], new ClientCredentials('id', 'secret'));
        $responseData = $this->adapter->token($request)->getBody();

        $this->assertEquals('/' . $this->basePath . '/token', $responseData['path']);

        $this->assertEquals($request->getParameters(), $responseData['postFields']);
        $this->assertEquals([], $responseData['queries']);

        $this->assertEquals($request->getCredentials()->getId(), $responseData['client_id']);
        $this->assertEquals($request->getCredentials()->getSecret(), $responseData['client_secret']);
    }

    /**
     *
     */
    public function test_introspect_throws_internal_exception_if_an_error_occurs()
    {
        $this->setExpectedException('Parroauth2\Client\Exception\InternalErrorException');

        $this->http->setResponse((new KangarooResponse())->setStatusCode(401));

        $this->adapter->introspect(new Request());
    }

    /**
     *
     */
    public function test_introspect_returns_authorization_data_properly()
    {
        $expectedResponse = new Response(['userId' => 'id']);

        $this->http->setResponse(
            (new KangarooResponse())
                ->setStatusCode(200)
                ->setBody($expectedResponse->getBody())
        );

        $response = $this->adapter->introspect(new Request());

        $this->assertEquals($expectedResponse, $response);
    }

    /**
     *
     */
    public function test_introspect_sends_request_data_properly()
    {
        $this->http->setResponse(function (KangarooRequest $request) {
            return new KangarooResponse(
                [
                    'path'          => $request->getPath(),
                    'postFields'    => $request->getPostFields(),
                    'queries'       => $request->getQueries(),
                    'client_id'     => $request->getHeader('client_id'),
                    'client_secret' => $request->getHeader('client_secret'),
                ],
                200
            );
        });

        $request = new Request(['some' => 'parameter'], new ClientCredentials('id', 'secret'));
        $responseData = $this->adapter->introspect($request)->getBody();

        $this->assertEquals('/' . $this->basePath . '/introspect', $responseData['path']);

        $this->assertEquals($request->getParameters(), $responseData['postFields']);
        $this->assertEquals([], $responseData['queries']);

        $this->assertEquals($request->getCredentials()->getId(), $responseData['client_id']);
        $this->assertEquals($request->getCredentials()->getSecret(), $responseData['client_secret']);
    }

    /**
     *
     */
    public function test_revoke_throws_internal_exception_if_an_error_occurs()
    {
        $this->setExpectedException('Parroauth2\Client\Exception\InternalErrorException');

        $this->http->setResponse((new KangarooResponse())->setStatusCode(401));

        $this->adapter->revoke(new Request());
    }

    /**
     *
     */
    public function test_revoke_returns_an_empty_response()
    {
        $this->http->setResponse((new KangarooResponse('', 200)));

        $this->assertEquals(new Response(), $this->adapter->revoke(new Request()));
    }

    /**
     *
     */
    public function test_revoke_sends_request_data_properly()
    {
        $asserted = false;
        $request = new Request(['some' => 'parameter'], new ClientCredentials('id', 'secret'));

        $this->http->setResponse(function (KangarooRequest $kangarooRequest) use ($request, &$asserted) {
            $this->assertEquals('/' . $this->basePath . '/revoke', $kangarooRequest->getPath());

            $this->assertEquals([], $kangarooRequest->getQueries());
            $this->assertEquals($request->getParameters(), $kangarooRequest->getPostFields());

            $this->assertEquals($request->getCredentials()->getId(), $kangarooRequest->getHeader('client_id'));
            $this->assertEquals($request->getCredentials()->getSecret(), $kangarooRequest->getHeader('client_secret'));

            $asserted = true;

            return new KangarooResponse('', 200);
        });

        $this->adapter->revoke($request)->getBody();

        if (!$asserted) {
            $this->fail('Http adapter send method seems not to be called');
        }
    }

    /**
     *
     */
    public function test_internalError_generates_exception_from_valid_minimal_rfc_error()
    {
        $response = (new KangarooResponse())
            ->setStatusCode(400)
            ->setBody((object)['error' => 'invalid_request'])
        ;

        $messageData = [
            'Configuration error',
            'Status code: ' . $response->getStatusCode(),
            'Error: ' . $response->getBody()->error,
        ];

        $expectedException = new InternalErrorException(implode(PHP_EOL, $messageData), 500);

        $class = new ReflectionClass('Parroauth2\Client\Adapters\KangarooAdapter');
        $method = $class->getMethod('internalError');
        $method->setAccessible(true);

        $this->assertEquals($expectedException, $method->invokeArgs($this->adapter, [$response]));
    }

    /**
     *
     */
    public function test_internalError_generates_exception_from_valid_rfc_error()
    {
        $response = (new KangarooResponse())
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

        $class = new ReflectionClass('Parroauth2\Client\Adapters\KangarooAdapter');
        $method = $class->getMethod('internalError');
        $method->setAccessible(true);

        $this->assertEquals($expectedException, $method->invokeArgs($this->adapter, [$response]));
    }

    /**
     *
     */
    public function test_internalError_generates_exception_from_body_as_string()
    {
        $response = (new KangarooResponse())
            ->setStatusCode(404)
            ->setBody('Page not found')
        ;

        $messageData = [
            'Configuration error',
            'Status code: ' . $response->getStatusCode(),
            'Error: ' . $response->getBody(),
        ];

        $expectedException = new InternalErrorException(implode(PHP_EOL, $messageData), 500);

        $class = new ReflectionClass('Parroauth2\Client\Adapters\KangarooAdapter');
        $method = $class->getMethod('internalError');
        $method->setAccessible(true);

        $this->assertEquals($expectedException, $method->invokeArgs($this->adapter, [$response]));
    }
}