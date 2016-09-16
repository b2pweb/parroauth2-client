<?php

namespace Parroauth2\Client\Tests;

use Bdf\PHPUnit\TestCase;
use DateTime;
use Parroauth2\Client\AuthorizationClient;
use Parroauth2\Client\Grant;
use Parroauth2\Client\Storage\MemoryStorage;
use Parroauth2\Client\Strategy\Authorization\AuthorizationStrategyInterface;

/**
 * Class AuthorizationClientTest
 * 
 * @package Parroauth2\Client
 *
 * @group Parroauth2
 * @group Parroauth2/Client
 * @group Parroauth2/Client/AuthorizationClient
 */
class AuthorizationClientTest extends TestCase
{
    /**
     * @var MemoryStorage
     */
    protected $storage;

    /**
     * @var AuthorizationClient
     */
    protected $client;

    /**
     * @var AuthorizationStrategyInterface
     */
    protected $strategy;

    /**
     * 
     */
    public function setUp()
    {
        $this->storage = new MemoryStorage();

        $this->strategy = $this->getMock('Parroauth2\Client\Strategy\Authorization\AuthorizationStrategyInterface', ['token', 'refresh', 'revoke']);

        $this->client = new AuthorizationClient(
            $this->strategy,
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
        $this->strategy
            ->expects($this->once())
            ->method('refresh')
            ->with($outdatedGrant)
            ->will($this->returnValue($grant))
        ;

        $this->assertSame($grant, $this->client->getGrant());
    }

    /**
     *
     */
    public function test_login_stores_token()
    {
        $expectedGrant = new Grant('access_token', new DateTime('tomorrow'), 'refresh_token', 'Bearer');

        $this->strategy
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
        $this->strategy
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
    public function test_logout_clears_token()
    {
        $grant = new Grant('access_token', new DateTime('tomorrow'), 'refresh_token', 'Bearer');

        $this->storage->store($grant);
        $this->strategy
            ->expects($this->once())
            ->method('revoke')
            ->with($grant)
        ;

        $this->client->logout();

        $this->assertFalse($this->storage->exists(), 'Grant still present in storage');
    }
}