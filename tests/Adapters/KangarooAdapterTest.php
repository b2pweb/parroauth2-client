<?php

namespace Parroauth2\Client\Tests\Adapters;

use Bdf\PHPUnit\TestCase;
use DateTime;
use Kangaroo\Client;
use Kangaroo\Request as KangarooRequest;
use Kangaroo\Response as KangarooResponse;
use Parroauth2\Client\Adapters\KangarooAdapter;
use Parroauth2\Client\ClientCredentials;
use Parroauth2\Client\Request;
use Parroauth2\Client\Response;
use Parroauth2\Client\Tests\Stubs\TestableHttpClientAdapter;

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
     * @dataProvider exceptionProvider
     *
     * @param object $error
     * @param string $exceptionClass
     */
    public function test_token_throws_exception_if_so($error, $exceptionClass)
    {
        $this->setExpectedException($exceptionClass, $error->error_description);

        $this->http->setResponse(
            (new KangarooResponse())
                ->setStatusCode(400)
                ->setBody($error)
        );

        $this->adapter->token(new Request());
    }

    /**
     *
     */
    public function exceptionProvider()
    {
        return [
            [(object)['error' => 'access_denied', 'error_description' => 'Access denied'], 'Parroauth2\Client\Exception\AccessDeniedException'],
            [(object)['error' => 'invalid_client', 'error_description' => 'Error description'], 'Parroauth2\Client\Exception\InvalidClientException'],
            [(object)['error' => 'invalid_grant', 'error_description' => 'Error description'], 'Parroauth2\Client\Exception\InvalidGrantException'],
            [(object)['error' => 'invalid_request', 'error_description' => 'Error description'], 'Parroauth2\Client\Exception\InvalidRequestException'],
            [(object)['error' => 'invalid_scope', 'error_description' => 'Error description'], 'Parroauth2\Client\Exception\InvalidScopeException'],
            [(object)['error' => 'server_error', 'error_description' => 'Server error'], 'Parroauth2\Client\Exception\ServerErrorException'],
            [(object)['error' => 'temporarily_unavailable', 'error_description' => 'Temporarily unavailable'], 'Parroauth2\Client\Exception\TemporarilyUnavailableException'],
            [(object)['error' => 'unauthorized_client', 'error_description' => 'Error description'], 'Parroauth2\Client\Exception\UnauthorizedClientException'],
            [(object)['error' => 'unsupported_grant_type', 'error_description' => 'Error description'], 'Parroauth2\Client\Exception\UnsupportedGrantTypeException'],
            [(object)['error' => 'unsupported_response_type', 'error_description' => 'Unsupported response type'], 'Parroauth2\Client\Exception\UnsupportedResponseTypeException'],
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
     * @runInSeparateProcess
     */
    public function test_authorize_redirects()
    {
        $request = new Request(['some' => 'parameter']);

        $this->adapter->authorize($request);

        $this->fail('Adapter should have exited the script');
    }

    /**
     *
     */
    public function test_authorize_redirects_runs_user_callback()
    {
        $request = new Request(['some' => 'parameter']);

        $data = [];

        $this->adapter->authorize($request, function($location) use (&$data) {
            $data['location'] = $location;
        });

        $this->assertEquals('http://localhost/oauth2/authorize?some=parameter', $data['location']);
    }

    /**
     * @dataProvider exceptionProvider
     *
     * @param object $error
     * @param string $exceptionClass
     */
    public function test_introspect_throws_exception_if_so($error, $exceptionClass)
    {
        $this->setExpectedException($exceptionClass, $error->error_description);

        $this->http->setResponse(
            (new KangarooResponse())
                ->setStatusCode(400)
                ->setBody($error)
        );

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
     * @dataProvider exceptionProvider
     *
     * @param object $error
     * @param string $exceptionClass
     */
    public function test_revoke_throws_exception_if_so($error, $exceptionClass)
    {
        $this->setExpectedException($exceptionClass, $error->error_description);

        $this->http->setResponse(
            (new KangarooResponse())
                ->setStatusCode(400)
                ->setBody($error)
        );

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
}