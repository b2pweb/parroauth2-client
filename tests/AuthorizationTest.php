<?php

namespace Parroauth2\Client\Tests;

use Bdf\PHPUnit\TestCase;
use Parroauth2\Client\Authorization;

/**
 * @group Parroauth2
 * @group Parroauth2/Client
 * @group Parroauth2/Client/Authorization
 */
class AuthorizationTest extends TestCase
{
    /**
     * 
     */
    public function test_default_values()
    {
        $authorization = new Authorization('access_token', 'bearer');

        $this->assertEquals('access_token', $authorization->accessToken());
        $this->assertEquals('bearer', $authorization->tokenType());
        $this->assertNull($authorization->refreshToken());
        $this->assertEquals(-1, $authorization->lifetime());
        $this->assertEquals([], $authorization->scopes());
    }

    /**
     *
     */
    public function test_constructor_values()
    {
        $authorization = new Authorization('access_token', 'bearer', 20, 'refresh_token', ['email']);

        $this->assertEquals('refresh_token', $authorization->refreshToken());
        $this->assertEquals(20, $authorization->lifetime());
        $this->assertEquals(['email'], $authorization->scopes());
    }

    /**
     *
     */
    public function test_set_get_access_token()
    {
        $authorization = new Authorization('access_token', 'bearer');
        $authorization->setAccessToken('other_token');
        $this->assertEquals('other_token', $authorization->accessToken());
    }

    /**
     *
     */
    public function test_set_get_refresh_token()
    {
        $authorization = new Authorization('access_token', 'bearer');
        $authorization->setRefreshToken('other_token');
        $this->assertEquals('other_token', $authorization->refreshToken());
    }

    /**
     *
     */
    public function test_set_get_lifetime_token()
    {
        $authorization = new Authorization('access_token', 'bearer');
        $authorization->setLifetime(20);
        $this->assertEquals(20, $authorization->lifetime());
    }

    /**
     *
     */
    public function test_set_get_token_type()
    {
        $authorization = new Authorization('access_token', 'bearer');
        $authorization->setTokenType('basic');
        $this->assertEquals('basic', $authorization->tokenType());
    }

    /**
     *
     */
    public function test_set_get_has_scopes()
    {
        $authorization = new Authorization('access_token', 'bearer');
        $authorization->setScopes(['email']);
        $this->assertEquals(['email'], $authorization->scopes());
        $this->assertTrue($authorization->hasScope('email'));
        $this->assertFalse($authorization->hasScope('name'));
    }

    /**
     *
     */
    public function test_can_be_refreshed()
    {
        $authorization = new Authorization('access_token', 'bearer');
        $this->assertFalse($authorization->canBeRefreshed());

        $authorization = new Authorization('access_token', 'bearer', -1, 'refresh_token');
        $this->assertTrue($authorization->canBeRefreshed());
    }

    /**
     *
     */
    public function test_is_expired()
    {
        $authorization = new Authorization('access_token', 'bearer');
        $this->assertFalse($authorization->isExpired());

        $authorization->setLifetime(1);
        $this->assertTrue($authorization->isExpired());

        $authorization->setLifetime(time() + 20);
        $this->assertFalse($authorization->isExpired());

        $authorization->setLifetime(time() + 20);
        $this->assertTrue($authorization->isExpired(30));
    }
}