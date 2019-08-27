<?php

namespace Parroauth2\Client\Tests\ClientAdapters;

use Bdf\PHPUnit\TestCase;
use DateTime;
use Parroauth2\Client\ClientAdapters\LocalIntrospectionClientAdapter;
use Parroauth2\Client\Credentials\ClientCredentials;
use Parroauth2\Client\Exception\InvalidRequestException;
use Parroauth2\Client\Request;
use Parroauth2\Client\Response;
use Parroauth2\Client\Unserializer\JwtUnserializer;

/**
 * @group Parroauth2
 * @group Parroauth2/Client
 * @group Parroauth2/Client/HttpClient
 * @group Parroauth2/Client/HttpClient/LocalIntrospectionClientAdapter
 */
class LocalIntrospectionClientAdapterTest extends TestCase
{
    /**
     * @var LocalIntrospectionClientAdapter
     */
    protected $client;

    /**
     * @var string
     */
    protected $privateKey;

    /**
     * @var string
     */
    protected $publicKey;

    /**
     *
     */
    public function setUp()
    {
        $this->privateKey = file_get_contents(__DIR__ . '/../oauth-private.key');
        $this->publicKey = file_get_contents(__DIR__ . '/../oauth-public.key');

        $unserializer = new JwtUnserializer($this->publicKey);

        $this->client = new LocalIntrospectionClientAdapter($unserializer);
    }

    /**
     *
     */
    public function test_token_is_not_available()
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('Access granting is not available');

        $this->client->token(new Request());
    }

    /**
     *
     */
    public function test_authorize_is_not_available()
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('Authorize procedure is not available');

        $this->client->getAuthorizationUri(new Request());
    }

    /**
     *
     */
    public function test_get_authorization_uri()
    {
        $unserializer = $this->createMock(JwtUnserializer::class);
        $delegate = $this->createMock(LocalIntrospectionClientAdapter::class);
        $delegate->expects($this->once())->method('getAuthorizationUri')->willReturn('bar');

        $this->client = new LocalIntrospectionClientAdapter($unserializer, $delegate);
        $request = new Request(['some' => 'parameter']);

        $location = $this->client->getAuthorizationUri($request);

        $this->assertEquals('bar', $location);
    }

    /**
     *
     */
    public function test_revoke_is_not_available()
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('Access revoking is not available');

        $this->client->revoke(new Request());
    }

    /**
     *
     */
    public function test_introspect_with_expired_token()
    {
        $data = ['exp' => (new DateTime('-1 hour'))->getTimestamp()];

        $token = $this->buildToken($data);

        $this->assertEquals(
            new Response(['active' => false]),
            $this->client->introspect(new Request(['token' => $token]))
        );
    }

    /**
     *
     */
    public function test_introspect_with_different_client_id()
    {
        $data = ['aud' => 'audience'];

        $token = $this->buildToken($data);

        $this->assertEquals(
            new Response(['active' => false]),
            $this->client->introspect(new Request(['token' => $token], [], new ClientCredentials('clientId', 'clientSecret')))
        );
    }

    /**
     *
     */
    public function test_introspect()
    {
        $data = [
            'scope' => 'scope',
            'username' => 'username',
            'token_type' => 'bearer',
            'exp' => (new DateTime('tomorrow'))->getTimestamp(),
            'iat' => (new DateTime('yesterday'))->getTimestamp(),
            'nbf' => (new DateTime('yesterday'))->getTimestamp(),
            'sub' => 'subject',
            'aud' => 'audience',
            'iss' => 'issuer',
            'jti' => 'token_id',
            'metadata' => (object)['meta' => 'data'],
        ];

        $token = $this->buildToken($data);

        $this->assertEquals(
            new Response(['active' => true, 'client_id' => $data['aud']] + $data),
            $this->client->introspect(new Request([], ['token' => $token]))
        );
    }

    /**
     * @param array $data
     *
     * @return string
     */
    protected function buildToken($data)
    {
        return \JWT::encode($data, $this->privateKey, 'RS256');
    }

    /**
     * @param array $source
     * @param string $key
     * @param mixed $default
     *
     * @return mixed
     */
    protected function extract(array $source, $key, $default = null)
    {
        if (!isset($source[$key])) {
            return $default;
        }

        return $source[$key];
    }
}