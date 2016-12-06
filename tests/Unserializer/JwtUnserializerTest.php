<?php

namespace Parroauth2\Client\Tests\Unserializer;

use Bdf\PHPUnit\TestCase;
use DateTime;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Parroauth2\Client\Exception\ParsingException;
use Parroauth2\Client\Unserializer\JwtUnserializer;

/**
 * Class JwtUnserializerTest
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
        $this->privateKey = 'file://' . __DIR__ . '/../oauth-private.key';
        $this->publicKey = 'file://' . __DIR__ . '/../oauth-public.key';

        $this->unserializer = new JwtUnserializer(new Parser(), $this->publicKey);
    }

    /**
     *
     */
    public function test_csrf()
    {
        $signer = new Sha256();
        $token = base64_encode($signer->sign('http://localhost', $this->privateKey)->__toString());

        $this->assertTrue($signer->verify(base64_decode($token), 'http://localhost', $this->publicKey));
    }

    /**
     *
     */
    public function test_decode_throws_parsing_exception_if_an_error_occurs()
    {
        $this->expectException(ParsingException::class);
        $this->expectExceptionMessage('Unable to unserialize token');

        $this->unserializer->unserialize('SomeWrongToken');
    }

    /**
     *
     */
    public function test_decode_throws_parsing_exception_if_token__cannot_be_verified()
    {
        $this->expectException(ParsingException::class);
        $this->expectExceptionMessage('Unable to verify token');

        $token = (new Builder())
            ->sign(new Sha256(), $this->privateKey)
            ->getToken()
            ->__toString()
        ;

        (new JwtUnserializer(
            new Parser(),
            'file://' . __DIR__ . '/../oauth-public-wrong.key'
        ))->unserialize($token);
    }

    /**
     *
     */
    public function test_decode()
    {
        $expected = [
            'scope'      => 'scope',
            'client_id'  => 'audience',
            'username'   => 'username',
            'token_type' => 'bearer',
            'exp'        => (new DateTime('tomorrow'))->getTimestamp(),
            'iat'        => (new DateTime('yesterday'))->getTimestamp(),
            'nbf'        => (new DateTime('yesterday'))->getTimestamp(),
            'sub'        => 'subject',
            'aud'        => 'audience',
            'iss'        => 'issuer',
            'jti'        => 'token_id',
            'metadata'   => (object)['userId' => 'id'],
        ];

        $token = (new Builder())
            ->setExpiration($expected['exp'])
            ->setIssuedAt($expected['iat'])
            ->setNotBefore($expected['nbf'])
            ->setSubject($expected['sub'])
            ->setAudience($expected['aud'])
            ->setIssuer($expected['iss'])
            ->setId($expected['jti'], true)

            ->set('scope', $expected['scope'])
            ->set('client_id', $expected['client_id'])
            ->set('username', $expected['username'])
            ->set('token_type', $expected['token_type'])
            ->set('metadata', $expected['metadata'])

            ->sign(new Sha256(), $this->privateKey)
            ->getToken()
            ->__toString()
        ;

        $this->assertEquals($expected, $this->unserializer->unserialize($token));
    }
}