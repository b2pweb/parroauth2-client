<?php

namespace Parroauth2\Client\OpenID\EndPoint\Userinfo;

use Parroauth2\Client\Client;
use Parroauth2\Client\ClientConfig;
use Parroauth2\Client\EndPoint\Token\TokenResponse;
use Parroauth2\Client\Exception\OAuthServerException;
use Parroauth2\Client\OpenID\EndPoint\Token\TokenEndPoint;
use Parroauth2\Client\Tests\FunctionalTestCase;

/**
 * Class UserinfoEndPointTest
 */
class UserinfoEndPointFunctionalTest extends FunctionalTestCase
{
    /**
     * @var Client
     */
    private $client;

    /**
     * @var TokenEndPoint
     */
    private $endPoint;

    protected function setUp(): void
    {
        parent::setUp();

        $this->client = $this->client(
            (new ClientConfig('test'))
                ->setSecret('my-secret')
                ->setScopes(['email', 'name'])
                ->enableOpenId(true)
        );
        $this->endPoint = new UserinfoEndPoint($this->client);
        $this->dataSet
            ->pushClient('test', 'my-secret', 'http://client.example.com')
            ->pushUser('bob', '$bob', ['name' => 'Bob', 'family_name' => 'Smith', 'email' => 'bob@example.com'])
            ->pushScopes(['email', 'profile'])
            ->setConnectedUser('bob')
        ;
    }

    /**
     *
     */
    public function test_functional_success()
    {
        $token = $this->token();

        $userinfo = $this->endPoint->token($token->accessToken())->call();

        $this->assertInstanceOf(UserinfoResponse::class, $userinfo);
        $this->assertEquals('bob', $userinfo->subject());
        $this->assertEquals('bob@example.com', $userinfo->email());
        $this->assertEquals('Bob', $userinfo->name());
        $this->assertEquals('Smith', $userinfo->familyName());
    }

    /**
     *
     */
    public function test_inHeader_functional()
    {
        $token = $this->token();

        $userinfo = $this->endPoint->token($token->accessToken())->inHeader()->call();

        $this->assertEquals('bob', $userinfo->subject());
    }

    /**
     *
     */
    public function test_inBody_functional()
    {
        $token = $this->token();

        $userinfo = $this->endPoint->token($token->accessToken())->inBody()->call();

        $this->assertEquals('bob', $userinfo->subject());
    }

    /**
     *
     */
    public function test_inQuery_functional()
    {
        $token = $this->token();

        $userinfo = $this->endPoint->token($token->accessToken())->inQuery()->call();

        $this->assertEquals('bob', $userinfo->subject());
    }

    /**
     *
     */
    public function test_functional_error()
    {
        $this->expectException(OAuthServerException::class);
        $this->expectExceptionMessage('The access token provided is invalid');

        $this->endPoint->token('invalid')->call();
    }

    private function token(): TokenResponse
    {
        $location = $this->httpClient->get($this->client->endPoints()->authorization()->code()->scope(['email', 'profile'])->uri())->getHeaderLine('Location');
        parse_str(explode('?', $location)[1], $parameters);

        $code = $parameters['code'];
        return $this->client->endPoints()->token()->code($code)->call();
    }
}
