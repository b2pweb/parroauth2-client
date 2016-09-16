<?php

namespace Parroauth2\Client\Tests;

use Bdf\PHPUnit\TestCase;
use DateTime;
use Parroauth2\Client\Client;
use Parroauth2\Client\Grant;
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
        $this->storage = new MemoryStorage();

        $this->client = new Client(
            $this->storage
        );
    }

    /**
     *
     */
    public function test_getGrant_returns_null_no_token_is_stored()
    {
        $this->assertNull($this->client->getGrant());
    }

    /**
     *
     */
    public function test_getGrant_returns_stored_grant()
    {
        $grant = new Grant('access_token', new DateTime('tomorrow'), 'refresh_token', 'Bearer');

        $this->storage->store($grant);

        $this->assertSame($grant, $this->client->getGrant());
    }

    /**
     *
     */
    public function test_getGrant_refreshes_his_token_before_returning_access_if_needed()
    {
        $outdatedGrant = new Grant('outdated_access_token', new DateTime('yesterday'), 'refresh_token', 'Bearer');
        $grant = new Grant('access_token', new DateTime('tomorrow'), 'updated_refresh_token', 'Bearer');

        $this->storage->store($outdatedGrant);
        $strategy = $this->getMock('Parroauth2\Client\Strategy\Authorization\AuthorizationStrategyInterface', ['token', 'refresh', 'revoke']);
        $strategy
            ->expects($this->once())
            ->method('refresh')
            ->with($outdatedGrant)
            ->will($this->returnValue($grant))
        ;
        $this->client->setAuthorizationStrategy($strategy);

        $this->assertSame($grant, $this->client->getGrant());
    }

    /**
     *
     */
    public function test_login_stores_token()
    {
        $expectedGrant = new Grant('access_token', new DateTime('tomorrow'), 'refresh_token', 'Bearer');

        $strategy = $this->getMock('Parroauth2\Client\Strategy\Authorization\AuthorizationStrategyInterface', ['token', 'refresh', 'revoke']);
        $strategy
            ->expects($this->once())
            ->method('token')
            ->with('invalid', 'credentials')
            ->will($this->returnValue($expectedGrant))
        ;
        $this->client->setAuthorizationStrategy($strategy);

        $this->client->login('invalid', 'credentials');

        $this->assertSame($expectedGrant, $this->storage->retrieve());
    }

    /**
     *
     */
    public function test_refresh_throws_connection_exception_if_no_token_is_set()
    {
        $this->setExpectedException('Parroauth2\Client\Exception\ConnectionException', 'Client is not connected');

        $this->client->refresh();
    }

    /**
     *
     */
    public function test_refresh_updates_stored_token()
    {
        $outdatedGrant = new Grant('outdated_access_token', new DateTime('yesterday'), 'refresh_token', 'Bearer');
        $grant = new Grant('access_token', new DateTime('tomorrow'), 'updated_refresh_token', 'Bearer');

        $this->storage->store($outdatedGrant);
        $strategy = $this->getMock('Parroauth2\Client\Strategy\Authorization\AuthorizationStrategyInterface', ['token', 'refresh', 'revoke']);
        $strategy
            ->expects($this->once())
            ->method('refresh')
            ->will($this->returnValue($grant))
        ;
        $this->client->setAuthorizationStrategy($strategy);

        $this->client->refresh();

        $this->assertSame($grant, $this->storage->retrieve());
    }

    /**
     *
     */
    public function test_introspect_throws_connection_exception_if_no_token_is_set()
    {
        $this->setExpectedException('Parroauth2\Client\Exception\ConnectionException', 'Client is not connected');

        $this->client->introspect();
    }

    /**
     *
     */
    public function test_introspect_returns_the_token_data()
    {
        $grant = new Grant('access_token', new DateTime('tomorrow'), 'refresh_token', 'Bearer');
        $expectedIntrospection = [
            'id'   => 123,
            'name' => 'Phpunit Instance',
            'role' => 'tester',
        ];

        $this->storage->store($grant);
        $strategy = $this->getMock('Parroauth2\Client\Strategy\Introspection\IntrospectionStrategyInterface', ['introspect']);
        $strategy
            ->expects($this->once())
            ->method('introspect')
            ->with($grant)
            ->will($this->returnValue($expectedIntrospection))
        ;
        $this->client->setIntrospectionStrategy($strategy);

        $this->assertEquals($expectedIntrospection, $this->client->introspect());
    }

    /**
     *
     */
    public function test_logout_clears_token()
    {
        $grant = new Grant('access_token', new DateTime('tomorrow'), 'refresh_token', 'Bearer');

        $this->storage->store($grant);
        $strategy = $this->getMock('Parroauth2\Client\Strategy\Authorization\AuthorizationStrategyInterface', ['token', 'refresh', 'revoke']);
        $strategy
            ->expects($this->once())
            ->method('revoke')
            ->with($grant)
        ;
        $this->client->setAuthorizationStrategy($strategy);

        $this->client->logout();

        $this->assertFalse($this->storage->exists(), 'Grant still present in storage');
    }
}