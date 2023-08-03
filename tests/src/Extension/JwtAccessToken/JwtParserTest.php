<?php

namespace Parroauth2\Client\Extension\JwtAccessToken;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Parroauth2\Client\Client;
use Parroauth2\Client\ClientConfig;
use Parroauth2\Client\Tests\UnitTestCase;

/**
 * Class JwtParserTest
 */
class JwtParserTest extends UnitTestCase
{
    /**
     * @var JwtParser
     */
    private $parser;

    /**
     * @var CompactSerializer
     */
    private $serializer;

    /**
     * @var Client
     */
    private $client;

    protected function setUp(): void
    {
        parent::setUp();

        $this->parser = new JwtParser();
        $this->client = $this->provider()->client((new ClientConfig('test')));
        $this->serializer = new CompactSerializer();
    }

    /**
     *
     */
    public function test_decode_success()
    {
        $jws = $this->jwsBuilder([new RS256()])
            ->create()
            ->addSignature(JWKFactory::createFromKeyFile(__DIR__.'/../../../keys/oauth-private.key'), ['alg' => 'RS256'])
            ->withPayload('{"foo":"bar"}')
            ->build()
        ;

        $jws = $this->serializer->serialize($jws);

        $decoded = $this->parser->parse($jws, $this->client);

        $this->assertEquals(['foo' => 'bar'], $decoded);
    }

    /**
     *
     */
    public function test_decode_with_key_in_option()
    {
        $this->client->clientConfig()->setOption('access_token_jwk', JWKFactory::createFromSecret('secretsecretsecretsecretsecretsecretsecretsecretsecret'));

        $jws = $this->jwsBuilder([new HS256()])
            ->create()
            ->addSignature(JWKFactory::createFromSecret('secretsecretsecretsecretsecretsecretsecretsecretsecret'), ['alg' => 'HS256'])
            ->withPayload('{"foo":"bar"}')
            ->build()
        ;

        $jws = $this->serializer->serialize($jws);

        $decoded = $this->parser->parse($jws, $this->client);

        $this->assertEquals(['foo' => 'bar'], $decoded);
    }

    /**
     *
     */
    public function test_decode_failed()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid JWT or signature');

        $this->parser->parse('invalid', $this->client);
    }

    private function jwsBuilder(array $algo): JWSBuilder
    {
        $ctor = (new \ReflectionClass(JWSBuilder::class))->getConstructor();

        return $ctor->getNumberOfParameters() === 1
            ? new JWSBuilder(new AlgorithmManager($algo))
            : new JWSBuilder(null, new AlgorithmManager($algo))
        ;
    }
}
