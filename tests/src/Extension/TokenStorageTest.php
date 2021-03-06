<?php

namespace Parroauth2\Client\Extension;

use BadMethodCallException;
use Parroauth2\Client\Client;
use Parroauth2\Client\ClientConfig;
use Parroauth2\Client\EndPoint\Token\RevocationEndPoint;
use Parroauth2\Client\Exception\OAuthServerException;
use Parroauth2\Client\Extension\JwtAccessToken\JwtParser;
use Parroauth2\Client\Extension\JwtAccessToken\LocalIntrospectionEndPoint;
use Parroauth2\Client\Tests\FunctionalTestCase;

/**
 * Class TokenStorageTest
 */
class TokenStorageTest extends FunctionalTestCase
{
    /**
     * @var Client
     */
    private $client;

    /**
     * @var TokenStorage
     */
    private $extension;

    protected function setUp(): void
    {
        parent::setUp();

        $this->dataSet
            ->declare()
            ->pushClient('test', 'my-secret', 'http://client.example.com')
            ->pushScopes(['email', 'profile'])
            ->pushUser('bob', '$bob')
            ->pushConfig('metadata', ['introspection_endpoint' => 'http://localhost:5000/instrospection'])
        ;

        $this->client = $this->client(
            (new ClientConfig('test'))
                ->setSecret('my-secret')
                ->enableOpenId(true)
        );
        $this->extension = new TokenStorage();
        $this->client->register($this->extension);
        $this->client->endPoints()->add(new LocalIntrospectionEndPoint($this->client, new JwtParser()));
    }

    /**
     *
     */
    public function test_configure_twice_should_not_modify_extension()
    {
        $pkce = new TokenStorage();

        $pkce->configure($this->client);
        $cloned = clone $pkce;

        $otherClient = $this->client((new ClientConfig('other')));
        $pkce->configure($otherClient);

        $this->assertEquals($cloned, $pkce);
    }

    /**
     *
     */
    public function test_token()
    {
        $this->assertTrue($this->extension->expired());
        $this->assertNull($this->extension->token());

        $token = $this->client->endPoints()->token()->password('bob', '$bob')->call();

        $this->assertFalse($this->extension->expired());
        $this->assertSame($token, $this->extension->token());

        $this->extension->clear();
        $this->assertTrue($this->extension->expired());
        $this->assertNull($this->extension->token());
    }

    /**
     *
     */
    public function test_userinfo_without_token()
    {
        $this->expectException(BadMethodCallException::class);
        $this->client->endPoints()->userinfo()->call();
    }

    /**
     *
     */
    public function test_userinfo_success()
    {
        $this->client->endPoints()->token()->password('bob', '$bob', ['openid'])->call();
        $userinfo = $this->client->endPoints()->userinfo()->call();

        $this->assertEquals('bob', $userinfo->subject());
    }

    /**
     *
     */
    public function test_revocation_success()
    {
        $token = $this->client->endPoints()->token()->password('bob', '$bob', ['openid'])->call();
        $endpoint = $this->client->endPoints()->revocation();

        $this->assertSame($token->accessToken(), $endpoint->get('token'));
        $endpoint->call();

        try {
            $this->client->endPoints()->userinfo()->token($token->accessToken())->call();
            $this->fail('Expects exception');
        } catch (OAuthServerException $e) {
            $this->assertEquals('The access token provided is invalid', $e->getMessage());
        }

        $this->assertNull($this->extension->token());
    }

    /**
     *
     */
    public function test_revocation_without_token()
    {
        $this->assertArrayNotHasKey('token', $this->client->endPoints()->revocation()->parameters());
    }

    /**
     *
     */
    public function test_introspection_without_token()
    {
        $this->assertArrayNotHasKey('token', $this->client->endPoints()->introspection()->parameters());
    }

    /**
     *
     */
    public function test_introspection_success()
    {
        $this->dataSet
            ->pushConfig('use_jwt_access_tokens', true)
        ;

        $token = $this->client->endPoints()->token()->password('bob', '$bob', ['openid'])->call();
        $endpoint = $this->client->endPoints()->introspection();

        $this->assertSame($token->accessToken(), $endpoint->get('token'));

        $introspection = $endpoint->call();
        $this->assertEquals('test', $introspection->audience());
        $this->assertEquals('bob', $introspection->subject());
    }

    /**
     *
     */
    public function test_introspection_with_expired_token_should_remove_from_storage()
    {
        $token = $this->client->endPoints()->token()->password('bob', '$bob', ['openid'])->call();
        $endpoint = $this->client->endPoints()->introspection();

        // Revoke token, ignoring the extension
        (new RevocationEndPoint($this->client))->accessToken($token->accessToken())->call();

        $introspection = $endpoint->call();
        $this->assertFalse($introspection->active());
        $this->assertNull($this->extension->token());
    }

    /**
     *
     */
    public function test_endSession_without_token()
    {
        $this->assertArrayNotHasKey('id_token_hint', $this->client->endPoints()->endSession()->parameters());
    }

    /**
     *
     */
    public function test_endSession_success()
    {
        $this->dataSet->pushConfig('connected_user', 'bob');
        $response = $this->provider->sendRequest($this->provider->request('GET', 'authorization', ['response_type' => 'code', 'scope' => 'openid', 'redirect_uri' => 'http://client.example.com', 'client_id' => $this->client->clientId(), 'state' => 'state']));

        parse_str(parse_url($response->getHeaderLine('Location'), PHP_URL_QUERY), $parameters);
        $token = $this->client->endPoints()->token()->code($parameters['code'], 'http://client.example.com')->call();
        $endpoint = $this->client->endPoints()->endSession();

        $this->assertSame((string) $token->idToken(), $endpoint->get('id_token_hint'));

        $this->assertEquals('http://localhost:5000/logout?id_token_hint='.$token->idToken(), $endpoint->uri());
    }
}
