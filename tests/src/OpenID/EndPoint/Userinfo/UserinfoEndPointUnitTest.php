<?php

namespace Parroauth2\Client\OpenID\EndPoint\Userinfo;

use GuzzleHttp\Psr7\Response;
use Parroauth2\Client\Client;
use Parroauth2\Client\ClientConfig;
use Parroauth2\Client\EndPoint\EndPointTransformerInterface;
use Parroauth2\Client\OpenID\EndPoint\Token\TokenEndPoint;
use Parroauth2\Client\Tests\UnitTestCase;

/**
 * Class UserinfoEndPointTest
 */
class UserinfoEndPointUnitTest extends UnitTestCase
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

        $this->client = $this->provider()->client(
            (new ClientConfig('test'))
                ->setSecret('my-secret')
                ->setScopes(['email', 'name'])
                ->enableOpenId(true)
        );
        $this->endPoint = new UserinfoEndPoint($this->client);
    }

    /**
     *
     */
    public function test_inHeader()
    {
        $this->httpClient->addResponse(new Response(200, ['Content-Type' => 'application/json'], json_encode(['sub' => 'bob'])));
        $userinfo = $this->endPoint->token('AT')->inHeader()->call();

        $this->assertEquals('bob', $userinfo->subject());
        $this->assertEquals('Bearer AT', $this->httpClient->getLastRequest()->getHeaderLine('Authorization'));
    }

    /**
     *
     */
    public function test_inBody()
    {
        $this->httpClient->addResponse(new Response(200, ['Content-Type' => 'application/json'], json_encode(['sub' => 'bob'])));
        $userinfo = $this->endPoint->token('AT')->inBody()->call();

        $this->assertEquals('bob', $userinfo->subject());
        $this->assertEquals('POST', (string) $this->httpClient->getLastRequest()->getMethod());
        $this->assertEquals('access_token=AT', (string) $this->httpClient->getLastRequest()->getBody());
    }

    /**
     *
     */
    public function test_inQuery()
    {
        $this->httpClient->addResponse(new Response(200, ['Content-Type' => 'application/json'], json_encode(['sub' => 'bob'])));
        $userinfo = $this->endPoint->token('AT')->inQuery()->call();

        $this->assertEquals('bob', $userinfo->subject());
        $this->assertEquals('GET', (string) $this->httpClient->getLastRequest()->getMethod());
        $this->assertEquals('access_token=AT', (string) $this->httpClient->getLastRequest()->getUri()->getQuery());
    }

    /**
     *
     */
    public function test_invalid_content_type()
    {
        $this->expectException(\BadMethodCallException::class);
        $this->expectExceptionMessage('The Content-Type text/plain is not supported');

        $this->httpClient->addResponse(new Response(200, ['Content-Type' => 'text/plain'], ''));
        $this->endPoint->token('AT')->call();
    }

    /**
     *
     */
    public function test_claims()
    {
        $this->httpClient->addResponse(new Response(200, ['Content-Type' => 'application/json'], json_encode([
            'sub' => 'sub',
            'name' => 'name',
            'given_name' => 'given_name',
            'family_name' => 'family_name',
            'middle_name' => 'middle_name',
            'nickname' => 'nickname',
            'preferred_username' => 'preferred_username',
            'profile' => 'profile',
            'picture' => 'picture',
            'website' => 'website',
            'email' => 'email',
            'email_verified' => true,
            'gender' => 'gender',
            'birthdate' => 'birthdate',
            'zoneinfo' => 'zoneinfo',
            'locale' => 'locale',
            'phone_number' => 'phone_number',
            'phone_number_verified' => true,
            'address' => ['address' => 'address'],
            'updated_at' => 123,
            'foo' => 'bar',
        ])));

        $userinfo = $this->endPoint->token('AT')->call();

        $this->assertEquals('sub', $userinfo->subject());
        $this->assertEquals('name', $userinfo->name());
        $this->assertEquals('given_name', $userinfo->givenName());
        $this->assertEquals('family_name', $userinfo->familyName());
        $this->assertEquals('middle_name', $userinfo->middleName());
        $this->assertEquals('nickname', $userinfo->nickname());
        $this->assertEquals('preferred_username', $userinfo->preferredUsername());
        $this->assertEquals('profile', $userinfo->profile());
        $this->assertEquals('picture', $userinfo->picture());
        $this->assertEquals('website', $userinfo->website());
        $this->assertEquals('email', $userinfo->email());
        $this->assertTrue($userinfo->emailVerified());
        $this->assertEquals('gender', $userinfo->gender());
        $this->assertEquals('birthdate', $userinfo->birthdate());
        $this->assertEquals('zoneinfo', $userinfo->zoneinfo());
        $this->assertEquals('locale', $userinfo->locale());
        $this->assertEquals('phone_number', $userinfo->phoneNumber());
        $this->assertTrue($userinfo->phoneNumberVerified());
        $this->assertEquals(['address' => 'address'], $userinfo->address());
        $this->assertEquals(123, $userinfo->updatedAt());
        $this->assertEquals('bar', $userinfo->claim('foo'));
        $this->assertEquals(404, $userinfo->claim('not_found', 404));
    }

    /**
     *
     */
    public function test_apply()
    {
        $ret = $this->createMock(UserinfoEndPoint::class);
        $transformer = $this->createMock(EndPointTransformerInterface::class);
        $transformer->expects($this->once())->method('onUserinfo')->with($this->endPoint)->willReturn($ret);

        $this->assertSame($ret, $this->endPoint->apply($transformer));
    }
}
