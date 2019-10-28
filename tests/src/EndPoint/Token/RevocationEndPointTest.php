<?php

namespace Parroauth2\Client\EndPoint\Token;

use Parroauth2\Client\Client;
use Parroauth2\Client\ClientConfig;
use Parroauth2\Client\EndPoint\EndPointTransformerInterface;
use Parroauth2\Client\Exception\OAuthServerException;
use Parroauth2\Client\OpenID\EndPoint\Token\TokenEndPoint;
use Parroauth2\Client\OpenID\EndPoint\Userinfo\UserinfoEndPoint;
use Parroauth2\Client\Tests\FunctionalTestCase;
use Psr\Http\Message\ResponseInterface;

/**
 * Class RevocationEndPointTest
 */
class RevocationEndPointTest extends FunctionalTestCase
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
                ->enableOpenId(true)
        );
        $this->endPoint = new RevocationEndPoint($this->client);
        $this->dataSet
            ->pushClient('test', 'my-secret', 'http://client.example.com')
            ->pushScopes(['email', 'profile'])
            ->pushUser('bob', '$bob')
            ->setConnectedUser('bob')
        ;
    }

    /**
     *
     */
    public function test_accessToken_success()
    {
        $this->expectException(OAuthServerException::class);
        $this->expectExceptionMessage('The access token provided is invalid');

        $token = $this->token();

        $this->endPoint->accessToken($token->accessToken())->call();
        (new UserinfoEndPoint($this->client))->token($token->accessToken())->call();
    }

    /**
     *
     */
    public function test_refreshToken_success()
    {
        $this->expectException(OAuthServerException::class);
        $this->expectExceptionMessage('Invalid refresh token');

        $token = $this->token();

        $this->endPoint->refreshToken($token->refreshToken())->call();
        $this->client->endPoints()->token()->refresh($token->refreshToken())->call();
    }

    /**
     *
     */
    public function test_onResponse()
    {
        $token = $this->token();

        $this->endPoint->accessToken($token->accessToken())
            ->onResponse(function ($response) use(&$parameter) { $parameter = $response; })
            ->call()
        ;

        $this->assertNotNull($parameter);
        $this->assertInstanceOf(ResponseInterface::class, $parameter);
    }

    /**
     *
     */
    public function test_apply()
    {
        $ret = $this->createMock(RevocationEndPoint::class);
        $transformer = $this->createMock(EndPointTransformerInterface::class);
        $transformer->expects($this->once())->method('onRevocation')->with($this->endPoint)->willReturn($ret);

        $this->assertSame($ret, $this->endPoint->apply($transformer));
    }

    private function token(): TokenResponse
    {
        $location = $this->httpClient->get($this->client->endPoints()->authorization()->code()->scope(['openid', 'offline_access'])->uri())->getHeaderLine('Location');
        parse_str(explode('?', $location)[1], $parameters);

        $code = $parameters['code'];
        return $this->client->endPoints()->token()->code($code)->call();
    }
}
