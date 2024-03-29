<?php

namespace Parroauth2\Client\OpenID\IdToken;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Parroauth2\Client\Client;
use Parroauth2\Client\ClientConfig;
use Parroauth2\Client\Tests\UnitTestCase;

/**
 * Class JwsIdTokenParserTest
 */
class JwsIdTokenParserTest extends UnitTestCase
{
    /**
     * @var JwsIdTokenParser
     */
    private $parser;

    /**
     * @var Client
     */
    private $client;

    protected function setUp(): void
    {
        parent::setUp();

        $this->parser = new JwsIdTokenParser();

        $this->client = $this->provider()->client(
            (new ClientConfig('test'))
                ->setSecret('azertyuiopqsdfghjklmwxcvbn0123456789')
        );
    }

    /**
     *
     */
    public function test_parse_success()
    {
        $jws = (new CompactSerializer())->serialize($this->builder()
            ->withPayload('{"foo":"bar","sid":"my_session_id"}')
            ->build()
        );

        $parsed = $this->parser->parse($this->client, $jws);

        $this->assertEquals($jws, (string) $parsed);
        $this->assertEquals($jws, $parsed->raw());
        $this->assertEquals(['foo' => 'bar', 'sid' => 'my_session_id'], $parsed->claims());
        $this->assertEquals(['alg' => 'RS256'], $parsed->headers());
        $this->assertEquals('my_session_id', $parsed->sid());
    }

    /**
     *
     */
    public function test_parse_success_with_symmetric_signature()
    {
        $jws = $this->jwsBuilder([new HS256()])
            ->create()
            ->addSignature(JWKFactory::createFromSecret('azertyuiopqsdfghjklmwxcvbn0123456789'), ['alg' => 'HS256'])
            ->withPayload('{"foo":"bar"}')
            ->build()
        ;

        $jws = (new CompactSerializer())->serialize($jws);

        $parsed = $this->parser->parse($this->client, $jws);

        $this->assertEquals($jws, (string) $parsed);
        $this->assertEquals($jws, $parsed->raw());
        $this->assertEquals(['foo' => 'bar'], $parsed->claims());
        $this->assertEquals(['alg' => 'HS256'], $parsed->headers());
    }

    /**
     *
     */
    public function test_parse_invalid_key()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid JWT or signature');

        $this->client = $this->provider(['jwks' => new JWKSet([
            JWKFactory::createFromKeyFile(__DIR__.'/../../../keys/oauth-public-wrong.key', null, ['use' => 'sig', 'alg' => 'RS256'])
        ])])->client((new ClientConfig('test')));

        $jws = (new CompactSerializer())->serialize($this->builder()
            ->withPayload('{"foo":"bar"}')
            ->build()
        );

        $this->parser->parse($this->client, $jws);
    }

    /**
     *
     */
    public function test_parse_invalid_key_with_symmetric_signature()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid JWT or signature');

        $jws = $this->jwsBuilder([new HS256()])
            ->create()
            ->addSignature(JWKFactory::createFromSecret('otherotherotherotherotherotherother'), ['alg' => 'HS256'])
            ->withPayload('{"foo":"bar"}')
            ->build()
        ;

        $jws = (new CompactSerializer())->serialize($jws);

        $this->parser->parse($this->client, $jws);
    }

    private function builder(): JWSBuilder
    {
        return $this->jwsBuilder([new RS256()])
            ->create()
            ->addSignature(JWKFactory::createFromKeyFile(__DIR__.'/../../../keys/oauth-private.key'), ['alg' => 'RS256'])
        ;
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
