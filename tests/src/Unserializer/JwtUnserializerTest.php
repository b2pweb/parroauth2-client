<?php

namespace Parroauth2\Client\Tests\Unserializer;

use PHPUnit\Framework\TestCase;
use DateTime;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256;
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
    public function setUp(): void
    {
        $this->privateKey = 'file://' . __DIR__ . '/../../keys/oauth-private.key';
        $this->publicKey = 'file://' . __DIR__ . '/../../keys/oauth-public.key';

        $this->unserializer = new JwtUnserializer($this->publicKey);
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
        $this->assertNull($this->unserializer->unserialize('SomeWrongToken'));
    }

    /**
     *
     */
    public function test_decode_throws_parsing_exception_if_token_cannot_be_verified()
    {
        $token = \JWT::encode([], $this->privateKey, 'RS256');

        $result = (new JwtUnserializer('file://' . __DIR__ . '/../../keys/oauth-public-wrong.key'))->unserialize($token);

        $this->assertNull($result);
    }

    /**
     *
     */
    public function test_decode()
    {
        $data = [
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

        $token = \JWT::encode($data, $this->privateKey, 'RS256');

        $builder = new Builder();
        foreach ($data as $key => $value) {
            $builder->withClaim($key, $value);
        }

        $this->assertEquals($builder->getToken(new Sha256(), new Key($this->privateKey)), $this->unserializer->unserialize($token));
    }
}
