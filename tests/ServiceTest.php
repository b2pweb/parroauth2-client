<?php

namespace Parroauth2\Client;

require_once __DIR__ . '/_files/TestableClientAdapter.php';

use Bdf\Config\Config;
use Bdf\PHPUnit\TestCase;
use Bdf\Session\Storage\MemoryStorage;
use DateTime;
use Kangaroo\Client as KangarooClient;
use Kangaroo\ClientAdapter\TestableClientAdapter;
use Kangaroo\Response;
use Parroauth2\Client\Client as ParroauthClient;

/**
 * Class ServiceTest
 * 
 * @package OAuth
 *
 * @group OAuth
 * @group OAuth/Service
 */
class ServiceTest extends TestCase
{
    /**
     * @var TestableClientAdapter
     */
    protected $adapter;

    /**
     * @var Service
     */
    protected $service;

    /**
     * 
     */
    public function setUp()
    {
        $storage = new MemoryStorage();

        $this->adapter = new TestableClientAdapter();

        $client = new ParroauthClient(
            new KangarooClient('http://localhost', $this->adapter),
            new Config([
                'clientId'     => 'clientId',
                'clientSecret' => 'clientSecret',
            ])
        );
        
        $this->service = new Service($client, $storage);
    }

    /**
     *
     */
    public function test_login_stores_token()
    {
        $tokenValidity = 3600;
        $expectedToken = new Token('access_token', (new DateTime())->setTimestamp(time() + ($tokenValidity * 0.9)), 'refresh_token');

        $response = new Response();
        $response
            ->setStatusCode(200)
            ->setBody((object)[
                'access_token'  => $expectedToken->getAccess(),
                'expires_in'    => $tokenValidity,
                'refresh_token' => $expectedToken->getRefresh(),
            ])
        ;

        $this->adapter->setResponse($response);

        $this->service->login('invalid', 'credentials');

        $token = $this->service->getToken();
        $this->assertEquals($expectedToken->getAccess(), $token->getAccess(), 'Error on access token');
        $this->assertEquals($expectedToken->getValidityEndpoint(), $token->getValidityEndpoint(), 'Error on token validity endpoint', 1);
        $this->assertEquals($expectedToken->getRefresh(), $token->getRefresh(), 'Error on refresh token');
    }

    /**
     *
     */
    public function test_refresh_throws_connection_exception_if_no_token_is_set()
    {
        $this->setExpectedException('Parroauth2\Client\Exception\ConnectionException', 'Not connected to service');

        $this->service->refresh();
    }

    /**
     *
     */
    public function test_refresh_updates_stored_token()
    {
        $tokenValidity = 3600;
        $expectedToken = new Token('updated_access_token', (new DateTime())->setTimestamp(time() + ($tokenValidity * 0.9)), 'updated_refresh_token');

        $response = new Response();
        $response
            ->setStatusCode(200)
            ->setBody((object)[
                'access_token'  => $expectedToken->getAccess(),
                'expires_in'    => $tokenValidity,
                'refresh_token' => $expectedToken->getRefresh(),
            ])
        ;

        $this->adapter->setResponse($response);

        $this->service
            ->setToken(new Token('access_token', new DateTime(), 'refresh_token'))
            ->refresh()
        ;

        $token = $this->service->getToken();
        $this->assertEquals($expectedToken->getAccess(), $token->getAccess(), 'Error on access token');
        $this->assertEquals($expectedToken->getValidityEndpoint(), $token->getValidityEndpoint(), 'Error on token validity endpoint', 1);
        $this->assertEquals($expectedToken->getRefresh(), $token->getRefresh(), 'Error on refresh token');
    }

    /**
     *
     */
    public function test_userinfo_throws_connection_exception_if_no_token_is_set()
    {
        $this->setExpectedException('Parroauth2\Client\Exception\ConnectionException', 'Not connected to service');

        $this->service->userinfo();
    }

    /**
     *
     */
    public function test_userinfo_returns_the_correct_data()
    {
        $expectedUserinfo = [
            'id'   => 123,
            'name' => 'Phpunit Instance',
            'role' => 'tester',
        ];

        $response = new Response();
        $response
            ->setStatusCode(200)
            ->setBody((object)$expectedUserinfo)
        ;

        $this->adapter->setResponse($response);

        $userinfo = $this->service
            ->setToken(new Token('access_token', new DateTime(), 'refresh_token'))
            ->userinfo()
        ;

        $this->assertEquals($expectedUserinfo, $userinfo);
    }

    /**
     *
     */
    public function test_introspect_returns_the_correct_data()
    {
        $expectedIntrospection = [
            'id'     => 123,
            'name'   => 'Phpunit Instance',
            'role'   => 'tester',
            'active' => true,
        ];

        $response = new Response();
        $response
            ->setStatusCode(200)
            ->setBody((object)$expectedIntrospection)
        ;

        $this->adapter->setResponse($response);

        $introspection = $this->service
            ->setToken(new Token('access_token', new DateTime(), 'refresh_token'))
            ->introspect()
        ;

        $this->assertEquals($expectedIntrospection, $introspection);
    }

    /**
     *
     */
    public function test_logout_resets_stored_token()
    {
        $this->service
            ->setToken(new Token('access_stoken', new DateTime(), 'refresh_token'))
            ->logout()
        ;

        $this->assertNull($this->service->getToken());
    }
}