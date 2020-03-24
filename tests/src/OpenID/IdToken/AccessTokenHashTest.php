<?php

namespace Parroauth2\Client\OpenID\IdToken;

use Bdf\PHPUnit\TestCase;

/**
 * Class AccessTokenHashTest
 */
class AccessTokenHashTest extends TestCase
{
    /**
     * @var AccessTokenHash
     */
    private $hash;

    protected function setUp(): void
    {
        $this->hash = new AccessTokenHash();
    }

    /**
     * @dataProvider provideAlg
     */
    public function test_compute($alg, $expected)
    {
        $this->assertEquals($expected, $this->hash->compute('at', $alg));
    }

    /**
     *
     */
    public function test_compute_invalid_alg()
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->hash->compute('at', 'invalid');
    }

    /**
     *
     */
    public function test_check()
    {
        $this->assertTrue($this->hash->check(new IdToken('', [], []), 'at'));
        $this->assertTrue($this->hash->check(new IdToken('', ['at_hash' => 'sda5G2fCr6XjIpiNlGJjjQ'], ['alg' => 'RS256']), 'at'));
        $this->assertFalse($this->hash->check(new IdToken('', ['at_hash' => 'invalid'], ['alg' => 'RS256']), 'at'));
    }

    public function provideAlg()
    {
        return [
            ['HS256', 'sda5G2fCr6XjIpiNlGJjjQ'],
            ['HS384', '4hulEO2T04y86FsZK2pA8fxDcRCCi6uc'],
            ['HS512', 'dTR5nNqNrsxqjWP_lCTH2ESWpeTv9f1yZraJ_wsSjjE'],
            ['RS256', 'sda5G2fCr6XjIpiNlGJjjQ'],
            ['RS384', '4hulEO2T04y86FsZK2pA8fxDcRCCi6uc'],
            ['RS512', 'dTR5nNqNrsxqjWP_lCTH2ESWpeTv9f1yZraJ_wsSjjE'],
            ['ES256', 'sda5G2fCr6XjIpiNlGJjjQ'],
            ['ES384', '4hulEO2T04y86FsZK2pA8fxDcRCCi6uc'],
            ['ES512', 'dTR5nNqNrsxqjWP_lCTH2ESWpeTv9f1yZraJ_wsSjjE'],
            ['PS256', 'sda5G2fCr6XjIpiNlGJjjQ'],
            ['PS384', '4hulEO2T04y86FsZK2pA8fxDcRCCi6uc'],
            ['PS512', 'dTR5nNqNrsxqjWP_lCTH2ESWpeTv9f1yZraJ_wsSjjE'],
        ];
    }
}
