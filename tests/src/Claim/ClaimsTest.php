<?php


namespace Parroauth2\Client\Claim;

use PHPUnit\Framework\TestCase;

/**
 * Class ClaimsTest
 */
class ClaimsTest extends TestCase
{
    /**
     * @var Claims
     */
    private $claims;

    /**
     *
     */
    protected function setUp(): void
    {
        $this->claims = new Claims(['foo' => 'bar', 'azerty' => 'uiop', 'value' => 42]);
    }

    /**
     *
     */
    public function test_array_access()
    {
        $this->assertSame('bar', $this->claims['foo']);
        $this->assertArrayHasKey('foo', $this->claims);
        $this->assertArrayNotHasKey('not_found', $this->claims);
    }

    /**
     *
     */
    public function test_array_set()
    {
        $this->expectException(\BadMethodCallException::class);

        $this->claims['other'] = 'value';
    }

    /**
     *
     */
    public function test_array_unset()
    {
        $this->expectException(\BadMethodCallException::class);

        unset($this->claims['foo']);
    }

    /**
     *
     */
    public function test_claim()
    {
        $this->assertSame('bar', $this->claims->claim('foo'));
        $this->assertSame('bar', $this->claims->claim('foo', 'other'));
        $this->assertNull($this->claims->claim('not_found'));
        $this->assertSame('other', $this->claims->claim('not_found', 'other'));
    }

    /**
     *
     */
    public function test_claims()
    {
        $this->assertSame(['foo' => 'bar', 'azerty' => 'uiop', 'value' => 42], $this->claims->claims());
    }

    /**
     *
     */
    public function test_has()
    {
        $this->assertTrue($this->claims->has('foo'));
        $this->assertFalse($this->claims->has('not_found'));
    }

    /**
     *
     */
    public function test_check()
    {
        $this->assertTrue($this->claims->check('foo', 'bar'));
        $this->assertFalse($this->claims->check('foo', 'rab'));
        $this->assertFalse($this->claims->check('foo', 0));

        $this->assertTrue($this->claims->check('not_found', null));
        $this->assertFalse($this->claims->check('not_found', ''));
        $this->assertFalse($this->claims->check('not_found', 0));

        $this->assertTrue($this->claims->check('value', 42));
        $this->assertFalse($this->claims->check('value', 43));
        $this->assertFalse($this->claims->check('value', 42.0));
    }

    /**
     *
     */
    public function test_checkAll()
    {
        $this->assertTrue($this->claims->checkAll([]));
        $this->assertTrue($this->claims->checkAll(['foo' => 'bar']));
        $this->assertFalse($this->claims->checkAll(['foo' => 'rab']));
        $this->assertTrue($this->claims->checkAll(['foo' => 'bar', 'value' => 42]));
        $this->assertFalse($this->claims->checkAll(['foo' => 'bar', 'value' => 40]));
    }
}
