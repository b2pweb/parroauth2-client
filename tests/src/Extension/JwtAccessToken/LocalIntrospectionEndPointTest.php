<?php

namespace Parroauth2\Client\Extension\JwtAccessToken;

use Jose\Component\Core\AlgorithmManager;
use Nyholm\Psr7\Response;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Parroauth2\Client\Client;
use Parroauth2\Client\ClientConfig;
use Parroauth2\Client\EndPoint\EndPointTransformerInterface;
use Parroauth2\Client\EndPoint\Introspection\IntrospectionEndPoint;
use Parroauth2\Client\EndPoint\Introspection\IntrospectionResponse;
use Parroauth2\Client\Factory\BaseClientFactory;
use Parroauth2\Client\Jwt\JWA;
use Parroauth2\Client\Provider\ProviderLoader;
use Parroauth2\Client\Tests\TestingDataSet;
use Parroauth2\Client\Tests\UnitTestCase;

/**
 * Class LocalIntrospectionEndPointTest
 */
class LocalIntrospectionEndPointTest extends UnitTestCase
{
    /**
     * @var Client
     */
    private $client;

    /**
     * @var LocalIntrospectionEndPoint
     */
    private $endPoint;

    protected function setUp(): void
    {
        parent::setUp();

        $this->client = $this->provider()->client(
            (new ClientConfig('test'))
                ->setSecret('my-secret')
                ->enableOpenId(true)
        );
        $this->endPoint = new LocalIntrospectionEndPoint($this->client, new JwtParser());
    }

    /**
     *
     */
    public function test_functional()
    {
        $dataSet = new TestingDataSet();
        $dataSet
            ->declare()
            ->pushClient('test', 'my-secret', 'http://client.example.com')
            ->pushScopes(['email', 'profile'])
            ->pushUser('bob', '$bob')
            ->pushConfig('use_jwt_access_tokens', true)
        ;

        $this->client = (new ProviderLoader(new BaseClientFactory($this->session)))->discover('http://localhost:5000')->client(
            (new ClientConfig('test'))
                ->setSecret('my-secret')
                ->enableOpenId(true)
        );

        $this->endPoint = new LocalIntrospectionEndPoint($this->client, new JwtParser());

        $token = $this->client->endPoints()->token()->password('bob', '$bob', ['email', 'profile'])->call();

        $introspection = $this->endPoint->accessToken($token->accessToken())->call();

        $this->assertEquals('http://localhost:5000', $introspection->issuer());
        $this->assertEquals('test', $introspection->audience());
        $this->assertEquals('bob', $introspection->subject());
        $this->assertEqualsWithDelta(time() + 3600, $introspection->expireAt(), 10);
        $this->assertEqualsWithDelta(time(), $introspection->issuedAt(), 10);
        $this->assertEquals('bearer', $introspection->tokenType());
        $this->assertEquals(['email', 'profile'], $introspection->scopes());
        $this->assertEquals('test', $introspection->clientId());

        $dataSet->destroy();
    }

    /**
     *
     */
    public function test_apply()
    {
        $ret = $this->createMock(IntrospectionEndPoint::class);
        $transformer = $this->createMock(EndPointTransformerInterface::class);
        $transformer->expects($this->once())->method('onIntrospection')->with($this->endPoint)->willReturn($ret);

        $this->assertSame($ret, $this->endPoint->apply($transformer));
    }

    /**
     *
     */
    public function test_not_access_token()
    {
        $this->httpClient->addResponse(new Response(200, [], json_encode(['active' => true, 'sub' => 123])));

        $response = $this->endPoint->refreshToken('RT')->call();

        $this->assertInstanceOf(IntrospectionResponse::class, $response);
        $this->assertTrue($response->active());
        $this->assertEquals(123, $response->subject());

        $this->assertEquals('POST', $this->httpClient->getLastRequest()->getMethod());
        $this->assertEquals('http://op.example.com/introspection', (string) $this->httpClient->getLastRequest()->getUri());
        $this->assertEquals('token=RT&token_type_hint=refresh_token', (string) $this->httpClient->getLastRequest()->getBody());
        $this->assertEquals('Basic dGVzdDpteS1zZWNyZXQ=', $this->httpClient->getLastRequest()->getHeaderLine('Authorization'));
    }

    /**
     *
     */
    public function test_not_jwt_access_token()
    {
        $this->httpClient->addResponse(new Response(200, [], json_encode(['active' => true, 'sub' => 123])));

        $response = $this->endPoint->accessToken('AT')->call();

        $this->assertInstanceOf(IntrospectionResponse::class, $response);
        $this->assertTrue($response->active());
        $this->assertEquals(123, $response->subject());

        $this->assertEquals('POST', $this->httpClient->getLastRequest()->getMethod());
        $this->assertEquals('http://op.example.com/introspection', (string) $this->httpClient->getLastRequest()->getUri());
        $this->assertEquals('token=AT&token_type_hint=access_token', (string) $this->httpClient->getLastRequest()->getBody());
        $this->assertEquals('Basic dGVzdDpteS1zZWNyZXQ=', $this->httpClient->getLastRequest()->getHeaderLine('Authorization'));
    }

    /**
     *
     */
    public function test_expired_jwt()
    {
        $jwa = new JWA();
        $key = JWKFactory::createFromKeyFile(__DIR__.'/../../../keys/oauth-private.key');
        $builder = $this->jwsBuilder($jwa->manager());

        $jws = $builder
            ->withPayload(json_encode([
                'sub' => '123',
                'jti' => '789',
                'exp' => time() - 100,
            ]))
            ->addSignature($key, ['alg' => 'RS256'])
            ->build()
        ;

        $response = $this->endPoint->accessToken((new CompactSerializer())->serialize($jws))->call();

        $this->assertEmpty($this->httpClient->getRequests());
        $this->assertFalse($response->active());
        $this->assertNull($response->subject());
        $this->assertNull($response->jwtId());
    }

    /**
     *
     */
    public function test_default_claims_values()
    {
        $jwa = new JWA();
        $key = JWKFactory::createFromKeyFile(__DIR__.'/../../../keys/oauth-private.key');
        $builder = $this->jwsBuilder($jwa->manager());

        $jws = $builder
            ->withPayload(json_encode([
                'exp' => time() + 100,
                'aud' => ['foo', 'bar'],
                'iss' => 'http://op.example.com',
            ]))
            ->addSignature($key, ['alg' => 'RS256'])
            ->build()
        ;

        $response = $this->endPoint->accessToken((new CompactSerializer())->serialize($jws))->call();

        $this->assertTrue($response->active());
        $this->assertEquals('foo', $response->clientId());
        $this->assertEquals('bearer', $response->tokenType());
    }

    /**
     *
     */
    public function test_wrong_issuer()
    {
        $jwa = new JWA();
        $key = JWKFactory::createFromKeyFile(__DIR__.'/../../../keys/oauth-private.key');
        $builder = $this->jwsBuilder($jwa->manager());

        $jws = $builder
            ->withPayload(json_encode([
                'exp' => time() + 100,
                'aud' => ['foo', 'bar'],
            ]))
            ->addSignature($key, ['alg' => 'RS256'])
            ->build()
        ;

        $response = $this->endPoint->accessToken((new CompactSerializer())->serialize($jws))->call();

        $this->assertFalse($response->active());
    }

    /**
     *
     */
    public function test_invalid_jwt_without_configured_endpoint_should_return_inactive_response()
    {
        $this->client = $this->provider(['introspection_endpoint' => null])->client(
            (new ClientConfig('test'))
                ->setSecret('my-secret')
                ->enableOpenId(true)
        );

        $this->endPoint = new LocalIntrospectionEndPoint($this->client, new JwtParser());

        $response = $this->endPoint->accessToken('AT')->call();

        $this->assertInstanceOf(IntrospectionResponse::class, $response);
        $this->assertFalse($response->active());

        $this->assertCount(0, $this->httpClient->getRequests());
    }

    private function jwsBuilder(AlgorithmManager $manager): JWSBuilder
    {
        $ctor = (new \ReflectionClass(JWSBuilder::class))->getConstructor();

        return $ctor->getNumberOfParameters() === 1
            ? new JWSBuilder($manager)
            : new JWSBuilder(null, $manager)
            ;
    }
}
