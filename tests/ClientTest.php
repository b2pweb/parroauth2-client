<?php

namespace Parroauth2\Client;

use Bdf\PHPUnit\TestCase;
use DateTime;
use Parroauth2\Client\Adapter\AdapterInterface;
use Parroauth2\Client\Storage\MemoryStorage;

/**
 * Class ClientTest
 * 
 * @package Parroauth2\Client
 *
 * @group Parroauth2
 * @group Parroauth2/Client
 * @group Parroauth2/Client/Client
 */
class ClientTest extends TestCase
{
    /**
     * @var AdapterInterface
     */
    protected $adapter;

    /**
     * @var MemoryStorage
     */
    protected $storage;

    /**
     * @var Client
     */
    protected $client;

    /**
     * 
     */
    public function setUp()
    {
        $this->adapter = $this->getMock('Parroauth2\Client\Adapter\AdapterInterface', ['token', 'refresh', 'userinfo', 'introspect', 'revoke']);
        
        $this->storage = new MemoryStorage();

        $this->client = new Client(
            $this->adapter,
            $this->storage
        );
    }

    /**
     *
     */
    public function test_getAccessToken_returns_an_empty_string_no_token_is_stored()
    {
        $this->assertEquals('', $this->client->getAccessToken());
    }

    /**
     *
     */
    public function test_getAccessToken_returns_access_token()
    {
        $grant = new Grant('access_token', new DateTime('tomorrow'), 'refresh_token');

        $this->storage->store($grant);

        $this->assertEquals($grant->getAccess(), $this->client->getAccessToken());
    }

    /**
     *
     */
    public function test_getAccessToken_refreshes_his_token_before_returning_access_if_needed()
    {
        $outdatedGrant = new Grant('outdated_access_token', new DateTime('yesterday'), 'refresh_token');
        $grant = new Grant('access_token', new DateTime('tomorrow'), 'updated_refresh_token');

        $this->storage->store($outdatedGrant);
        $this->adapter
            ->expects($this->once())
            ->method('refresh')
            ->with($outdatedGrant)
            ->will($this->returnValue($grant))
        ;

        $this->assertEquals($grant->getAccess(), $this->client->getAccessToken());
    }

    /**
     *
     */
    public function test_login_stores_token()
    {
        $expectedGrant = new Grant('access_token', new DateTime('tomorrow'), 'refresh_token');

        $this->adapter
            ->expects($this->once())
            ->method('token')
            ->with('invalid', 'credentials')
            ->will($this->returnValue($expectedGrant))
        ;

        $this->client->login('invalid', 'credentials');

        $this->assertSame($expectedGrant, $this->storage->retrieve());
    }

    /**
     *
     */
    public function test_refresh_throws_connection_exception_if_no_token_is_set()
    {
        $this->setExpectedException('Parroauth2\Client\Exception\ConnectionException', 'Not connected to service');

        $this->client->refresh();
    }

    /**
     *
     */
    public function test_refresh_updates_stored_token()
    {
        $outdatedGrant = new Grant('outdated_access_token', new DateTime('yesterday'), 'refresh_token');
        $grant = new Grant('access_token', new DateTime('tomorrow'), 'updated_refresh_token');

        $this->storage->store($outdatedGrant);
        $this->adapter
            ->expects($this->once())
            ->method('refresh')
            ->will($this->returnValue($grant))
        ;

        $this->client->refresh();

        $this->assertSame($grant, $this->storage->retrieve());
    }

    /**
     *
     */
    public function test_userinfo_throws_connection_exception_if_no_token_is_set()
    {
        $this->setExpectedException('Parroauth2\Client\Exception\ConnectionException', 'Not connected to service');

        $this->client->userinfo();
    }

    /**
     *
     */
    public function test_userinfo_returns_the_token_data()
    {
        $grant = new Grant('access_token', new DateTime('tomorrow'), 'refresh_token');
        $expectedUserinfo = [
            'id'   => 123,
            'name' => 'Phpunit Instance',
            'role' => 'tester',
        ];

        $this->storage->store($grant);
        $this->adapter
            ->expects($this->once())
            ->method('userinfo')
            ->with($grant)
            ->will($this->returnValue($expectedUserinfo))
        ;

        $this->assertEquals($expectedUserinfo, $this->client->userinfo());
    }

    /**
     *
     */
    public function test_introspect_throws_connection_exception_if_no_token_is_set()
    {
        $this->setExpectedException('Parroauth2\Client\Exception\ConnectionException', 'Not connected to service');

        $this->client->introspect();
    }

    /**
     *
     */
    public function test_introspect_returns_the_token_data()
    {
        $grant = new Grant('access_token', new DateTime('tomorrow'), 'refresh_token');
        $expectedIntrospection = [
            'id'   => 123,
            'name' => 'Phpunit Instance',
            'role' => 'tester',
        ];

        $this->storage->store($grant);
        $this->adapter
            ->expects($this->once())
            ->method('introspect')
            ->with($grant)
            ->will($this->returnValue($expectedIntrospection))
        ;

        $this->assertEquals($expectedIntrospection, $this->client->introspect());
    }

    /**
     *
     */
    public function test_logout_clears_token()
    {
        $grant = new Grant('access_token', new DateTime('tomorrow'), 'refresh_token');

        $this->storage->store($grant);
        $this->adapter
            ->expects($this->once())
            ->method('revoke')
            ->with($grant)
        ;

        $this->client->logout();

        $this->assertFalse($this->storage->exists(), 'Grant still present in storage');
    }
}