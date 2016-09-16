<?php

namespace Parroauth2\Client\Tests\Strategy\Introspection;

use Bdf\PHPUnit\TestCase;
use DateTime;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Parroauth2\Client\Grant;
use Parroauth2\Client\Parser\JwtParser;
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
 * @group Parroauth2/Client/Strategy/Introspection/SelfIntrospectionStrategyTest
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

        $parser = new JwtParser();
        $parser->setPublicKey($this->publicKey);

        $this->strategy = new SelfIntrospectionStrategy($parser);
    }

    /**
     *
     */
    public function test_introspect()
    {
        $metadata = [
            'id' => 123,
            'name' => 'Phpunit',
        ];

        $access_token = (new Builder())
            ->set('metadata', $metadata)
            ->sign(new Sha256(), $this->privateKey)
            ->getToken()
            ->__toString()
        ;

        $grant = new Grant(
            $access_token,
            new DateTime('tomorrow'),
            'refresh_token',
            'Bearer'
        );

        $this->assertEquals(
            $metadata,
            (array)$this->strategy->introspect($grant)
        );
    }
}