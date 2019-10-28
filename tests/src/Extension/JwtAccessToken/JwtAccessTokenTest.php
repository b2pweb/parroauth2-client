<?php

namespace Parroauth2\Client\Extension\JwtAccessToken;

use Parroauth2\Client\Client;
use Parroauth2\Client\ClientConfig;
use Parroauth2\Client\Tests\FunctionalTestCase;

/**
 * Class JwtAccessTokenTest
 */
class JwtAccessTokenTest extends FunctionalTestCase
{
    /**
     * @var Client
     */
    private $client;

    protected function setUp(): void
    {
        parent::setUp();

        $this->dataSet
            ->declare()
            ->pushClient('test', 'my-secret', 'http://client.example.com')
            ->pushScopes(['email', 'profile'])
            ->pushUser('bob', '$bob')
            ->pushConfig('use_jwt_access_tokens', true)
        ;

        $this->client = $this->client(
            (new ClientConfig('test'))
                ->setSecret('my-secret')
                ->enableOpenId(true)
        );
        $this->client->register(new JwtAccessToken());
    }

    /**
     *
     */
    public function test_introspection()
    {
        $this->assertInstanceOf(LocalIntrospectionEndPoint::class, $this->client->endPoints()->introspection());

        $token = $this->client->endPoints()->token()->password('bob', '$bob')->call();
        $introspection = $this->client->endPoints()->introspection()->accessToken($token->accessToken())->call();

        $this->assertTrue($introspection->active());
        $this->assertNotEmpty($introspection->jwtId());
    }
}
