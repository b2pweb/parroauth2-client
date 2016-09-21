<?php

namespace Parroauth2\Client\Tests\Unserializer;

use Bdf\PHPUnit\TestCase;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Parroauth2\Client\Unserializer\JwtUnserializer;

/**
 * Class JwtUnserializerTest
 *
 * @package Parroauth2\Client\Unserializer
 *
 * @group Parroauth2
 * @group Parroauth2/Client
 * @group Parroauth2/Client/Unserializer
 * @group Parroauth2/Client/Unserializer/JwtUnserializer
 */
class JwtUnserializerTest extends TestCase
{
    /**
     * @var string
     */
    protected $privateKey;

    /**
     * @var string
     */
    protected $publicKey;

    /**
     * @var JwtUnserializer
     */
    protected $unserializer;

    /**
     *
     */
    public function setUp()
    {
        $this->privateKey = file_get_contents(__DIR__ . '/../oauth-private.key');
        $this->publicKey = file_get_contents(__DIR__ . '/../oauth-public.key');

        $this->unserializer = new JwtUnserializer(new Parser(), $this->publicKey);
    }
    
    /**
     * 
     */
    public function test_decode()
    {
        $scope = 'scope1 scope2';
        $metadata = [
            'id' => 123,
            'name' => 'Phpunit',
        ];

        $token = (new Builder())
            ->set('scope', $scope)
            ->set('metadata', $metadata)
            ->sign(new Sha256(), $this->privateKey)
            ->getToken()
            ->__toString()
        ;

        $this->assertEquals(
            [
                'active'   => false,
                'scope'    => $scope,
                'metadata' => (object)$metadata,
                'exp'      => 0,
            ],
            $this->unserializer->unserialize($token)
        );
    }

    /**
     *
     */
    public function test_decode_throws_parsing_exception_if_an_error_occurs()
    {
        $this->setExpectedException('Parroauth2\Client\Exception\ParsingException', 'Unable to unserialize token');

        $this->unserializer->unserialize('SomeWrongToken');
    }

    /**
     *
     */
    public function test_decode_throws_parsing_exception_if_token__cannot_be_verified()
    {
        $this->setExpectedException('Parroauth2\Client\Exception\ParsingException', 'Unable to verify token');

        $token = (new Builder())
            ->sign(new Sha256(), $this->privateKey)
            ->getToken()
            ->__toString()
        ;

        (new JwtUnserializer(
            new Parser(),
            file_get_contents(__DIR__ . '/../oauth-public-wrong.key')
        ))->unserialize($token);
    }
}