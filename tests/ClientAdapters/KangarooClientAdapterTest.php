<?php

namespace Parroauth2\Client\Tests\ClientAdapters;

use Bdf\PHPUnit\TestCase;
use DateTime;
use Kangaroo\Client;
use Kangaroo\Request as KangarooRequest;
use Kangaroo\Response as KangarooResponse;
use Parroauth2\Client\ClientAdapters\KangarooClientAdapter;
use Parroauth2\Client\Credentials\ClientCredentials;
use Parroauth2\Client\Exception\AccessDeniedException;
use Parroauth2\Client\Exception\InvalidClientException;
use Parroauth2\Client\Exception\InvalidGrantException;
use Parroauth2\Client\Exception\InvalidRequestException;
use Parroauth2\Client\Exception\InvalidScopeException;
use Parroauth2\Client\Exception\ServerErrorException;
use Parroauth2\Client\Exception\TemporarilyUnavailableException;
use Parroauth2\Client\Exception\UnauthorizedClientException;
use Parroauth2\Client\Exception\UnsupportedGrantTypeException;
use Parroauth2\Client\Exception\UnsupportedResponseTypeException;
use Parroauth2\Client\Request;
use Parroauth2\Client\Response;
use Parroauth2\Client\Tests\Stubs\TestableHttpClientAdapter;

/**
 * @group Parroauth2
 * @group Parroauth2/Client
 * @group Parroauth2/Client/HttpClient
 * @group Parroauth2/Client/HttpClient/KangarooClientAdapter
 */
class KangarooClientAdapterTest extends TestCase
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
     * @var KangarooClientAdapter
     */
    protected $client;

    /**
     *
     */
    public function setUp()
    {
        $this->http = new TestableHttpClientAdapter();
        $this->basePath = 'oauth2';
        $this->client = new KangarooClientAdapter((new Client('http://localhost', $this->http))->api($this->basePath));
    }

    /**
     * @dataProvider exceptionProvider
     *
     * @param object $error
     * @param string $exceptionClass
     */
    public function test_token_throws_exception_if_so($error, $exceptionClass)
    {
        $this->expectException($exceptionClass);
        $this->expectExceptionMessage($error->error_description);

        $this->http->setResponse(
            (new KangarooResponse())
                ->setStatusCode(400)
                ->setBody($error)
        );

        $this->client->token(new Request());
    }

    /**
     *
     */
    public function exceptionProvider()
    {
        return [
            [(object)['error' => 'access_denied',             'error_description' => 'Access denied'],             AccessDeniedException::class],
            [(object)['error' => 'invalid_client',            'error_description' => 'Error description'],         InvalidClientException::class],
            [(object)['error' => 'invalid_grant',             'error_description' => 'Error description'],         InvalidGrantException::class],
            [(object)['error' => 'invalid_request',           'error_description' => 'Error description'],         InvalidRequestException::class],
            [(object)['error' => 'invalid_scope',             'error_description' => 'Error description'],         InvalidScopeException::class],
            [(object)['error' => 'server_error',              'error_description' => 'Server error'],              ServerErrorException::class],
            [(object)['error' => 'temporarily_unavailable',   'error_description' => 'Temporarily unavailable'],   TemporarilyUnavailableException::class],
            [(object)['error' => 'unauthorized_client',       'error_description' => 'Error description'],         UnauthorizedClientException::class],
            [(object)['error' => 'unsupported_grant_type',    'error_description' => 'Error description'],         UnsupportedGrantTypeException::class],
            [(object)['error' => 'unsupported_response_type', 'error_description' => 'Unsupported response type'], UnsupportedResponseTypeException::class],
        ];
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

        $response = $this->client->token(new Request());

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
                    'path'          => $request->getBasePath(),
                    'pathInfo'      => $request->getPathInfo(),
                    'postFields'    => $request->getBody()->data(),
                    'queries'       => $request->getQueries(),
                    'authorization' => $request->getHeader('Authorization'),
                ],
                200
            );
        });

        $request = new Request(['some' => 'query'], ['some' => 'post'], new ClientCredentials('id', 'secret'));
        $responseData = $this->client->token($request)->getBody();

        $this->assertEquals('/'.$this->basePath, $responseData['path']);
        $this->assertEquals('/token', $responseData['pathInfo']);
        $this->assertEquals($request->attributes(), $responseData['postFields']);
        $this->assertEquals($request->queries(), $responseData['queries']);
        $this->assertEquals($request->header('Authorization', 'notnull'), $responseData['authorization']);
    }

    /**
     *
     */
    public function test_get_authorizeation_uri()
    {
        $request = new Request(['some' => 'parameter']);

        $location = $this->client->getAuthorizationUri($request);

        $this->assertEquals('http://localhost/oauth2/authorize?some=parameter', $location);
    }

    /**
     * @dataProvider exceptionProvider
     *
     * @param object $error
     * @param string $exceptionClass
     */
    public function test_introspect_throws_exception_if_so($error, $exceptionClass)
    {
        $this->expectException($exceptionClass);
        $this->expectExceptionMessage($error->error_description);

        $this->http->setResponse(
            (new KangarooResponse())
                ->setStatusCode(400)
                ->setBody($error)
        );

        $this->client->introspect(new Request());
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

        $response = $this->client->introspect(new Request());

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
                    'path'          => $request->getBasePath(),
                    'pathInfo'      => $request->getPathInfo(),
                    'postFields'    => $request->getBody()->data(),
                    'queries'       => $request->getQueries(),
                    'authorization' => $request->getHeader('Authorization'),
                ],
                200
            );
        });

        $request = new Request(['some' => 'query'], ['some' => 'post'], new ClientCredentials('id', 'secret'));
        $responseData = $this->client->introspect($request)->getBody();

        $this->assertEquals('/'.$this->basePath, $responseData['path']);
        $this->assertEquals('/introspect', $responseData['pathInfo']);
        $this->assertEquals($request->attributes(), $responseData['postFields']);
        $this->assertEquals($request->queries(), $responseData['queries']);
        $this->assertEquals($request->header('Authorization', 'notnull'), $responseData['authorization']);
    }

    /**
     * @dataProvider exceptionProvider
     *
     * @param object $error
     * @param string $exceptionClass
     */
    public function test_revoke_throws_exception_if_so($error, $exceptionClass)
    {
        $this->expectException($exceptionClass);
        $this->expectExceptionMessage($error->error_description);

        $this->http->setResponse(
            (new KangarooResponse())
                ->setStatusCode(400)
                ->setBody($error)
        );

        $this->client->revoke(new Request());
    }

    /**
     *
     */
    public function test_revoke_returns_an_empty_response()
    {
        $this->http->setResponse((new KangarooResponse('', 200)));

        $this->assertEquals(new Response(), $this->client->revoke(new Request()));
    }

    /**
     *
     */
    public function test_revoke_sends_request_data_properly()
    {
        $asserted = false;
        $request = new Request(['some' => 'query'], ['some' => 'post'], new ClientCredentials('id', 'secret'));

        $this->http->setResponse(function (KangarooRequest $kangarooRequest) use ($request, &$asserted) {
            $this->assertEquals('/'.$this->basePath, $kangarooRequest->getBasePath());
            $this->assertEquals('/revoke', $kangarooRequest->getPathInfo());
            $this->assertEquals($request->attributes(), $kangarooRequest->getBody()->data());
            $this->assertEquals($request->queries(), $kangarooRequest->getQueries());
            $this->assertEquals($request->header('Authorization', 'notnull'), $kangarooRequest->getHeader('Authorization'));

            $asserted = true;

            return new KangarooResponse('', 200);
        });

        $this->client->revoke($request)->getBody();

        if (!$asserted) {
            $this->fail('Http client send method seems not to be called');
        }
    }
}