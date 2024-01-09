<?php

namespace Parroauth2\Client\EndPoint\Introspection;

use B2pweb\Jwt\JWT;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use Nyholm\Psr7\Response;
use Parroauth2\Client\Authentication\BasicClientAuthenticationMethod;
use Parroauth2\Client\Authentication\ClientAuthenticationMethodInterface;
use Parroauth2\Client\Authentication\JwtBearerClientAuthenticationMethod;
use Parroauth2\Client\Authentication\RequestBodyClientAuthenticationMethod;
use Parroauth2\Client\Client;
use Parroauth2\Client\ClientConfig;
use Parroauth2\Client\EndPoint\Token\TokenEndPoint;
use Parroauth2\Client\Jwt\JwtDecoder;
use Parroauth2\Client\Tests\UnitTestCase;

class InstrospectionEndPointAuthenticationTest extends UnitTestCase
{
    /**
     * @var Client
     */
    private $client;

    /**
     * @var IntrospectionEndPoint
     */
    private $endPoint;

    protected function setUp(): void
    {
        parent::setUp();

        $this->client = $this->provider()->client(
            (new ClientConfig('test'))
                ->setSecret('my-secretmy-secretmy-secretmy-secretmy-secretmy-secret')
                ->setScopes(['email', 'name'])
                ->enableOpenId(false)
        );
        $this->endPoint = new IntrospectionEndPoint($this->client);
    }

    /**
     *
     */
    public function test_with_jwt_bearer_unit()
    {
        $this->client->clientConfig()->setOption(ClientAuthenticationMethodInterface::OPTION_PREFERRED_METHOD, JwtBearerClientAuthenticationMethod::NAME);

        $this->httpClient->addResponse(new Response(200, [], json_encode(['foo' => 'bar'])));
        $this->endPoint->accessToken('my-access-token')->call();

        $request = $this->httpClient->getLastRequest();

        $this->assertEquals('application/x-www-form-urlencoded', $request->getHeaderLine('Content-Type'));
        $this->assertEmpty($request->getHeader('Authorization'));

        parse_str((string) $request->getBody(), $body);

        $this->assertSame('urn:ietf:params:oauth:client-assertion-type:jwt-bearer', $body['client_assertion_type']);

        $jwt = JWT::fromJwtUnsafe($body['client_assertion']);
        $this->assertEquals(['alg' => 'HS256'], $jwt->headers());
        $this->assertEqualsWithDelta([
            'iss' => 'test',
            'sub' => 'test',
            'aud' => 'http://op.example.com/introspection',
            'exp' => time() + 30,
            'iat' => time(),
            'nbf' => time(),
            'jti' => $jwt->payload()['jti'],
        ], $jwt->payload(), 2);

        $this->assertRegExp('/[a-zA-Z0-9-_]{32}/', $jwt->payload()['jti']);

        (new JwtDecoder())->decode($body['client_assertion'],
            new JWKSet([
                JWKFactory::createFromSecret($this->client->secret(), ['alg' => 'HS256'])
            ])
        );
    }

    /**
     *
     */
    public function test_basic_auth_unit()
    {
        $this->client->clientConfig()->setOption(ClientAuthenticationMethodInterface::OPTION_PREFERRED_METHOD, BasicClientAuthenticationMethod::NAME);

        $this->httpClient->addResponse(new Response(200, [], json_encode(['foo' => 'bar'])));
        $this->endPoint->accessToken('my-access-token')->call();

        $request = $this->httpClient->getLastRequest();

        $this->assertEquals('Basic dGVzdDpteS1zZWNyZXRteS1zZWNyZXRteS1zZWNyZXRteS1zZWNyZXRteS1zZWNyZXRteS1zZWNyZXQ=', $request->getHeaderLine('Authorization'));
    }

    /**
     *
     */
    public function test_with_request_body_auth_unit()
    {
        $this->client->clientConfig()->setOption(ClientAuthenticationMethodInterface::OPTION_PREFERRED_METHOD, RequestBodyClientAuthenticationMethod::NAME);

        $this->httpClient->addResponse(new Response(200, [], json_encode(['foo' => 'bar'])));
        $this->endPoint->accessToken('my-access-token')->call();

        $request = $this->httpClient->getLastRequest();

        $this->assertEquals('application/x-www-form-urlencoded', $request->getHeaderLine('Content-Type'));
        $this->assertEmpty($request->getHeader('Authorization'));

        parse_str((string) $request->getBody(), $body);

        $this->assertSame('test', $body['client_id']);
        $this->assertSame('my-secretmy-secretmy-secretmy-secretmy-secretmy-secret', $body['client_secret']);
    }
}
