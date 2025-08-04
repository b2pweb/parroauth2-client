<?php

namespace Parroauth2\Client\EndPoint\Token;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;

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
        $this->assertEqualsWithDelta(new \DateTime('+10 seconds'), (new TokenResponse(['expires_in' => 10]))->expiresAt(), 1);
        $this->assertEqualsWithDelta(new \DateTime(), (new TokenResponse(['expires_in' => 0]))->expiresAt(), 1);
    }

    /**
     *
     */
    public function test_expiresAt_with_clock()
    {
        $clock = new class implements ClockInterface
        {
            /**
             * @inheritDoc
             */
            public function now(): DateTimeImmutable
            {
                return new DateTimeImmutable('2025-06-23 12:00:00');
            }
        };

        $this->assertNull((TokenResponse::create([], $clock))->expiresAt());
        $this->assertNull((TokenResponse::create(['expires_in' => -1], $clock))->expiresAt());
        $this->assertEqualsWithDelta(new \DateTimeImmutable('2025-06-23 12:00:10'), (TokenResponse::create(['expires_in' => 10], $clock))->expiresAt(), 1);
        $this->assertEqualsWithDelta(new \DateTimeImmutable('2025-06-23 12:00:00'), (TokenResponse::create(['expires_in' => 0], $clock))->expiresAt(), 1);
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
    public function test_expired_with_clock()
    {
        $clock = new class implements ClockInterface {
            public DateTimeImmutable $date;

            public function now(): DateTimeImmutable
            {
                return $this->date;
            }
        };

        $clock->date = new DateTimeImmutable('2025-06-23 12:00:00');

        $this->assertFalse((TokenResponse::create([], $clock))->expired($clock));
        $this->assertFalse((TokenResponse::create(['expires_in' => 10], $clock))->expired($clock));

        $response = TokenResponse::create(['expires_in' => 10], $clock);
        $clock->date = new DateTimeImmutable('2025-06-23 12:00:11');

        $this->assertTrue($response->expired($clock));
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
