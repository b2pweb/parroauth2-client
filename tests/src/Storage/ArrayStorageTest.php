<?php

namespace Parroauth2\Client\Storage;

use PHPUnit\Framework\TestCase;

/**
 * Class ArrayStorageTest
 */
class ArrayStorageTest extends TestCase
{
    /**
     *
     */
    public function test_store()
    {
        $storage = new ArrayStorage();

        $storage->store('foo', 'bar');
        $this->assertTrue($storage->has('foo'));
        $this->assertEquals('bar', $storage->retrieve('foo'));
        $this->assertEquals(['foo' => 'bar'], $storage->all());

        $storage->store('oof', 'rab');
        $this->assertTrue($storage->has('oof'));
        $this->assertEquals('rab', $storage->retrieve('oof'));
        $this->assertEquals(['foo' => 'bar', 'oof' => 'rab'], $storage->all());
    }

    /**
     *
     */
    public function test_retrieve()
    {
        $storage = new ArrayStorage(['foo' => 'bar']);

        $this->assertEquals('bar', $storage->retrieve('foo', 404));
        $this->assertEquals(404, $storage->retrieve('not found', 404));
        $this->assertNull($storage->retrieve('not found'));
    }

    /**
     *
     */
    public function test_remove()
    {
        $storage = new ArrayStorage(['foo' => 'bar']);

        $this->assertEquals('bar', $storage->remove('foo'));
        $this->assertFalse($storage->has('foo'));
        $this->assertNull($storage->retrieve('not found'));
    }
}
