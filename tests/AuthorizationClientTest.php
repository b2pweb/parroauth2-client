<?php

namespace Parroauth2\Client\Tests;

use Bdf\PHPUnit\TestCase;
use DateTime;
use Parroauth2\Client\AuthorizationClient;
use Parroauth2\Client\Grant;
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
        $this->strategy = $this->getMock('Parroauth2\Client\Strategy\Authorization\AuthorizationStrategyInterface', ['token', 'refresh', 'revoke']);

        $this->client = new AuthorizationClient($this->strategy);
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

        $grant = $this->client->login('invalid', 'credentials');

        $this->assertSame($expectedGrant, $grant);
    }

    /**
     *
     */
    public function test_refresh_throws_connection_exception_if_no_token_is_set()
    {
        $this->setExpectedException('Parroauth2\Client\Exception\InternalErrorException', 'Unable to refresh empty token');

        $this->client->refresh('');
    }

    /**
     *
     */
    public function test_refresh_updates_stored_token()
    {
        $outdatedGrant = new Grant('outdated_access_token', new DateTime('yesterday'), 'refresh_token', 'Bearer');
        $expectedGrant = new Grant('access_token', new DateTime('tomorrow'), 'updated_refresh_token', 'Bearer');

        $this->strategy
            ->expects($this->once())
            ->method('refresh')
            ->with($outdatedGrant->getRefresh())
            ->will($this->returnValue($expectedGrant))
        ;

        $grant = $this->client->refresh($outdatedGrant);

        $this->assertSame($expectedGrant, $grant);
    }

    /**
     *
     */
    public function test_logout_revokes_token()
    {
        $grant = new Grant('access_token', new DateTime('tomorrow'), 'refresh_token', 'Bearer');

        $this->strategy
            ->expects($this->once())
            ->method('revoke')
            ->with($grant->getAccess())
        ;

        $this->client->logout($grant);
    }
}