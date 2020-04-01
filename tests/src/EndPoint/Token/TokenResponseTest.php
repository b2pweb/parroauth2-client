<?php

namespace Parroauth2\Client\EndPoint\Token;

use PHPUnit\Framework\TestCase;

/**
 * Class TokenResponseTest
 */
class TokenResponseTest extends TestCase
{
    /**
     *
     */
    public function test_expiresAt()
    {
        $this->assertNull((new TokenResponse([]))->expiresAt());
        $this->assertNull((new TokenResponse(['expires_in' => -1]))->expiresAt());
        $this->assertEquals(new \DateTime('+10 seconds'), (new TokenResponse(['expires_in' => 10]))->expiresAt(), '', 1);
        $this->assertEquals(new \DateTime(), (new TokenResponse(['expires_in' => 0]))->expiresAt(), '', 1);
    }

    /**
     *
     */
    public function test_expired()
    {
        $this->assertFalse((new TokenResponse([]))->expired());
        $this->assertFalse((new TokenResponse(['expires_in' => 10]))->expired());

        $response = new TokenResponse(['expires_in' => 1]);
        sleep(1);

        $this->assertTrue($response->expired());
    }

    /**
     *
     */
    public function test_getters()
    {
        $response = new TokenResponse([
            'access_token' => 'at',
            'refresh_token' => 'rt',
            'token_type' => 'Bearer',
            'scope' => 'email name'
        ]);

        $this->assertEquals('at', $response->accessToken());
        $this->assertEquals('rt', $response->refreshToken());
        $this->assertEquals('bearer', $response->type());
        $this->assertEquals(['email', 'name'], $response->scopes());

        $this->assertNull((new TokenResponse([]))->refreshToken());
        $this->assertNull((new TokenResponse([]))->scopes());
    }
}
