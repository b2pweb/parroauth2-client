<?php

namespace Parroauth2\Client\Tests;

use Bdf\PHPUnit\TestCase;
use Kangaroo\Client as KangarooClient;
use Kangaroo\Response as KangarooResponse;
use Parroauth2\Client\Adapters\AdapterInterface;
use Parroauth2\Client\Adapters\KangarooAdapter;
use Parroauth2\Client\Client;
use Parroauth2\Client\Authorization;
use Parroauth2\Client\GrantTypes\AuthorizationGrantType;
use Parroauth2\Client\GrantTypes\PasswordGrantType;
use Parroauth2\Client\GrantTypes\RefreshGrantType;
use Parroauth2\Client\Introspection;
use Parroauth2\Client\Request;
use Parroauth2\Client\Tests\Stubs\TestableHttpClientAdapter;
use PHPUnit_Framework_MockObject_MockBuilder;

/**
 * Class ClientTest
 * 
 * @group Parroauth2
 * @group Parroauth2/Client
 * @group Parroauth2/Client/Client
 */
class ClientTest extends TestCase
{
    /**
     * @var TestableHttpClientAdapter
     */
    protected $http;

    /**
     * @var AdapterInterface
     */
    protected $adapter;

    /**
     * @var Client
     */
    protected $client;

    /**
     *
     */
    public function setUp()
    {
        $this->http = new TestableHttpClientAdapter();
        $this->adapter = new KangarooAdapter((new KangarooClient('http://localhost', $this->http))->api('/oauth2'));
        $this->client = new Client($this->adapter);
    }

    /**
     *
     */
    public function test_unit_login_calls_token()
    {
        $expectedAuthorization = new Authorization('access_token', 'Bearer', 0, 'refresh_token', ['scope']);
        $username = 'username';
        $password = 'password';

        $client = $this->getMockBuilder(Client::class)
            ->disableOriginalConstructor()
            ->setMethods(['token'])
            ->getMock();
        ;
        $client
            ->expects($this->once())
            ->method('token')
            ->with(new PasswordGrantType($username, $password, $expectedAuthorization->getScopes()))
            ->willReturn($expectedAuthorization)
        ;

        $this->assertSame($expectedAuthorization, $client->login($username, $password, $expectedAuthorization->getScopes()));
    }

    /**
     *
     */
    public function test_unit_refresh_calls_token()
    {
        $expectedAuthorization = new Authorization('access_token', 'Bearer', 0, 'refresh_token', ['scope']);
        $token = 'token';

        $client = $this->getMockBuilder(Client::class)
            ->disableOriginalConstructor()
            ->setMethods(['token'])
            ->getMock();
        ;
        $client
            ->expects($this->once())
            ->method('token')
            ->with(new RefreshGrantType($token, $expectedAuthorization->getScopes()))
            ->willReturn($expectedAuthorization)
        ;

        $this->assertSame($expectedAuthorization, $client->refresh($token, $expectedAuthorization->getScopes()));
    }

    /**
     *
     */
    public function test_unit_tokenFromAuthorizationCode_calls_token()
    {
        $expectedAuthorization = new Authorization('access_token', 'Bearer', 0, 'refresh_token', ['scope']);
        $code = 'code';
        $redirectUri = 'https://my-app/home';
        $clientId = 'clientId';

        $client = $this->getMockBuilder(Client::class)
            ->disableOriginalConstructor()
            ->setMethods(['token'])
            ->getMock();
        ;
        $client
            ->expects($this->once())
            ->method('token')
            ->with(new AuthorizationGrantType($code, $redirectUri, $clientId))
            ->willReturn($expectedAuthorization)
        ;

        $this->assertSame($expectedAuthorization, $client->tokenFromAuthorizationCode($code, $redirectUri, $clientId));
    }

    /**
     *
     */
    public function test_token_provides_authorization_from_password_grant_type()
    {
        $expectedAuthorization = new Authorization('access_token', 'Bearer', 3600, 'refresh_token', ['scope']);
        $username = 'username';
        $password = 'password';

        $this->http->setResponse(new KangarooResponse((object)[
            'access_token'  => $expectedAuthorization->getAccess(),
            'token_type'    => $expectedAuthorization->getType(),
            'expires_in'    => $expectedAuthorization->getLifetime(),
            'refresh_token' => $expectedAuthorization->getRefresh(),
            'scope'         => implode(' ', $expectedAuthorization->getScopes()),
        ]));
        
        $this->assertEquals($expectedAuthorization, $this->client->token(new PasswordGrantType($username, $password, $expectedAuthorization->getScopes())));
    }

    /**
     *
     */
    public function test_token_provides_authorization_from_refresh_grant_type()
    {
        $expectedAuthorization = new Authorization('access_token', 'Bearer', 3600, 'refresh_token', ['scope']);
        $token = 'token';

        $this->http->setResponse(new KangarooResponse((object)[
            'access_token'  => $expectedAuthorization->getAccess(),
            'token_type'    => $expectedAuthorization->getType(),
            'expires_in'    => $expectedAuthorization->getLifetime(),
            'refresh_token' => $expectedAuthorization->getRefresh(),
            'scope'         => implode(' ', $expectedAuthorization->getScopes()),
        ]));

        $this->assertEquals($expectedAuthorization, $this->client->token(new RefreshGrantType($token, $expectedAuthorization->getScopes())));
    }

    /**
     *
     */
    public function test_token_provides_authorization_from_authorization_grant_type()
    {
        $expectedAuthorization = new Authorization('access_token', 'Bearer', 3600, 'refresh_token', ['scope']);
        $code = 'code';
        $redirectUri = 'https://my-app/home';
        $clientId = 'clientId';

        $this->http->setResponse(new KangarooResponse((object)[
            'access_token'  => $expectedAuthorization->getAccess(),
            'token_type'    => $expectedAuthorization->getType(),
            'expires_in'    => $expectedAuthorization->getLifetime(),
            'refresh_token' => $expectedAuthorization->getRefresh(),
            'scope'         => implode(' ', $expectedAuthorization->getScopes()),
        ]));

        $this->assertEquals($expectedAuthorization, $this->client->token(new AuthorizationGrantType($code, $redirectUri, $clientId)));
    }

    /**
     *
     */
    public function test_authorize_provides_authorization()
    {
        $expectedAuthorization = new Authorization('access_token', 'Bearer', 3600, 'refresh_token', ['scope']);
        $code = 'code';
        $redirectUri = 'http://localhost';
        $clientId = 'some_id';

        $this->http->setResponse(new KangarooResponse((object)[
            'access_token'  => $expectedAuthorization->getAccess(),
            'token_type'    => $expectedAuthorization->getType(),
            'expires_in'    => $expectedAuthorization->getLifetime(),
            'refresh_token' => $expectedAuthorization->getRefresh(),
            'scope'         => implode(' ', $expectedAuthorization->getScopes()),
        ]));

        $this->assertEquals($expectedAuthorization, $this->client->token(new AuthorizationGrantType($code, $redirectUri, $clientId)));
    }

    /**
     *
     */
    public function test_introspect_provides_introspection()
    {
        $expectedIntrospection = (new Introspection())
            ->setActive(true)
            ->setScopes(['scope1', 'scope2'])
            ->setMetadata(['meta1' => 'data1', 'meta2' => 'data2'])
        ;

        $this->http->setResponse(new KangarooResponse((object)[
            'active'   => true,
            'scope' => implode(' ', $expectedIntrospection->getScopes()),
            'metadata' => (object)$expectedIntrospection->getMetadata(),
        ]));

        $this->assertEquals($expectedIntrospection, $this->client->introspect('token'));
    }

    /**
     *
     */
    public function test_unit_revoke()
    {
        $token = 'token';
        $hint = 'access_token';

        $this->adapter = $this->getMockBuilder(AdapterInterface::class)
            ->disableOriginalConstructor()
            ->setMethods(['token', 'authorize', 'introspect', 'revoke'])
            ->getMock();
        ;
        $this->adapter
            ->expects($this->once())
            ->method('revoke')
            ->with(new Request([
                'token'           => $token,
                'token_type_hint' => $hint,
            ]))
        ;

        (new Client($this->adapter))->revoke($token, $hint);
    }
}