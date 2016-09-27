<?php

namespace Parroauth2\Client\Tests\Strategy\Introspection;

use Bdf\PHPUnit\TestCase;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Parroauth2\Client\Unserializer\JwtUnserializer;
use Parroauth2\Client\Introspection;
use Parroauth2\Client\Strategy\Introspection\SelfIntrospectionStrategy;

/**
 * Class SelfIntrospectionStrategyTest
 * 
 * @package Parroauth2\Client\Strategy\Introspection
 * 
 * @group Parroauth2
 * @group Parroauth2/Client
 * @group Parroauth2/Client/Strategy
 * @group Parroauth2/Client/Strategy/Introspection
 * @group Parroauth2/Client/Strategy/Introspection/SelfIntrospectionStrategy
 */
class SelfIntrospectionStrategyTest extends TestCase
{
    /**
     * @var SelfIntrospectionStrategy
     */
    protected $strategy;

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
        $this->privateKey = file_get_contents(__DIR__ . '/../../oauth-private.key');
        $this->publicKey = file_get_contents(__DIR__ . '/../../oauth-public.key');

        $parser = new JwtUnserializer(new Parser(), $this->publicKey);

        $this->strategy = new SelfIntrospectionStrategy($parser);
    }

    /**
     *
     */
    public function test_introspect()
    {
        $scopes = ['scope1', 'scope2'];
        $metadata = [
            'id' => 123,
            'name' => 'Phpunit',
        ];

        $token = (new Builder())
            ->set('scope', implode(' ', $scopes))
            ->set('metadata', $metadata)
            ->sign(new Sha256(), $this->privateKey)
            ->getToken()
            ->__toString()
        ;

        $introspection = new Introspection(true, $scopes, $metadata);

        $this->assertEquals(
            $introspection,
            $this->strategy->introspect($token)
        );
    }
}