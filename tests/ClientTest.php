<?php

namespace Parroauth2\Client\Tests;

use Bdf\PHPUnit\TestCase;
use Kangaroo\Client as KangarooClient;
use Kangaroo\Response as KangarooResponse;
use Parroauth2\Client\ClientAdapters\ClientAdapterInterface;
use Parroauth2\Client\ClientAdapters\KangarooClientAdapter;
use Parroauth2\Client\Client;
use Parroauth2\Client\Authorization;
use Parroauth2\Client\GrantTypes\AuthorizationGrantType;
use Parroauth2\Client\GrantTypes\PasswordGrantType;
use Parroauth2\Client\GrantTypes\RefreshGrantType;
use Parroauth2\Client\Introspection;
use Parroauth2\Client\Request;
use Parroauth2\Client\Response;
use Parroauth2\Client\Tests\Stubs\TestableHttpClientAdapter;

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
     * @var ClientAdapterInterface
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
        $this->adapter = new KangarooClientAdapter((new KangarooClient('http://localhost', $this->http))->api('/oauth2'));
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

        $client = $this->createPartialMock(Client::class, ['token']);
        $client
            ->expects($this->once())
            ->method('token')
            ->with(new PasswordGrantType($username, $password, $expectedAuthorization->scopes()))
            ->willReturn($expectedAuthorization)
        ;

        $this->assertSame($expectedAuthorization, $client->login($username, $password, $expectedAuthorization->scopes()));
    }

    /**
     *
     */
    public function test_unit_refresh_calls_token()
    {
        $expectedAuthorization = new Authorization('access_token', 'Bearer', 0, 'refresh_token', ['scope']);
        $token = 'token';

        $client = $this->createPartialMock(Client::class, ['token']);
        $client
            ->expects($this->once())
            ->method('token')
            ->with(new RefreshGrantType($token, $expectedAuthorization->scopes()))
            ->willReturn($expectedAuthorization)
        ;

        $this->assertSame($expectedAuthorization, $client->refresh($token, $expectedAuthorization->scopes()));
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

        $client = $this->createPartialMock(Client::class, ['token']);
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
            'access_token'  => $expectedAuthorization->accessToken(),
            'token_type'    => $expectedAuthorization->tokenType(),
            'expires_in'    => $expectedAuthorization->lifetime(),
            'refresh_token' => $expectedAuthorization->refreshToken(),
            'scope'         => implode(' ', $expectedAuthorization->scopes()),
        ]));
        
        $this->assertEquals($expectedAuthorization, $this->client->token(new PasswordGrantType($username, $password, $expectedAuthorization->scopes())));
    }

    /**
     *
     */
    public function test_token_provides_authorization_from_refresh_grant_type()
    {
        $expectedAuthorization = new Authorization('access_token', 'Bearer', 3600, 'refresh_token', ['scope']);
        $token = 'token';

        $this->http->setResponse(new KangarooResponse((object)[
            'access_token'  => $expectedAuthorization->accessToken(),
            'token_type'    => $expectedAuthorization->tokenType(),
            'expires_in'    => $expectedAuthorization->lifetime(),
            'refresh_token' => $expectedAuthorization->refreshToken(),
            'scope'         => implode(' ', $expectedAuthorization->scopes()),
        ]));

        $this->assertEquals($expectedAuthorization, $this->client->token(new RefreshGrantType($token, $expectedAuthorization->scopes())));
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
            'access_token'  => $expectedAuthorization->accessToken(),
            'token_type'    => $expectedAuthorization->tokenType(),
            'expires_in'    => $expectedAuthorization->lifetime(),
            'refresh_token' => $expectedAuthorization->refreshToken(),
            'scope'         => implode(' ', $expectedAuthorization->scopes()),
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
            'access_token'  => $expectedAuthorization->accessToken(),
            'token_type'    => $expectedAuthorization->tokenType(),
            'expires_in'    => $expectedAuthorization->lifetime(),
            'refresh_token' => $expectedAuthorization->refreshToken(),
            'scope'         => implode(' ', $expectedAuthorization->scopes()),
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
            'scope' => implode(' ', $expectedIntrospection->scopes()),
            'metadata' => (object)$expectedIntrospection->metadata(),
        ]));

        $this->assertEquals($expectedIntrospection, $this->client->introspect('token'));
    }

    /**
     *
     */
    public function test_unit_introspection()
    {
        $token = 'token';
        $hint = 'access_token';

        $this->adapter = $this->createMock(ClientAdapterInterface::class);
        $this->adapter
            ->expects($this->once())
            ->method('introspect')
            ->with(new Request([], [
                'token'           => $token,
                'token_type_hint' => $hint,
            ]))
            ->willReturn(new Response())
        ;

        (new Client($this->adapter))->introspect($token, $hint);
    }

    /**
     *
     */
    public function test_unit_revoke()
    {
        $token = 'token';
        $hint = 'access_token';

        $this->adapter = $this->createMock(ClientAdapterInterface::class);
        $this->adapter
            ->expects($this->once())
            ->method('revoke')
            ->with(new Request([], [
                'token'           => $token,
                'token_type_hint' => $hint,
            ]))
        ;

        (new Client($this->adapter))->revoke($token, $hint);
    }

    /**
     *
     */
    public function test_get_authorization_uri()
    {
        $uri = 'http://localhost/foo/bar';
        $clientId = 'b2pweb';

        $this->adapter = $this->createMock(ClientAdapterInterface::class);
        $this->adapter
            ->expects($this->once())
            ->method('getAuthorizationUri')
            ->with(new Request([
                'response_type' => 'code',
                'redirect_uri'  => $uri,
                'client_id'  => $clientId,
            ]))
            ->willReturn($uri)
        ;

        $redirect = (new Client($this->adapter))->getAuthorizationUri($uri, null, null, $clientId);

        $this->assertEquals($uri, $redirect);
    }
}