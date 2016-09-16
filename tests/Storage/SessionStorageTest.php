<?php

namespace Parroauth2\Client\Tests\Storage;

use Bdf\PHPUnit\TestCase;
use Bdf\Session\Storage\MemoryStorage;
use DateTime;
use Parroauth2\Client\Grant;
use Parroauth2\Client\Storage\SessionStorage;

/**
 * Class SessionStorageTest
 *
 * @package Parroauth2\Client\Storage
 *
 * @group Parroauth2
 * @group Parroauth2/Client
 * @group Parroauth2/Client/Storage
 * @group Parroauth2/Client/SessionStorage
 */
class SessionStorageTest extends TestCase
{
    /**
     * @var MemoryStorage
     */
    protected $baseStorage;

    /**
     * @var SessionStorage
     */
    protected $storage;

    public function setUp()
    {
        $this->baseStorage = new MemoryStorage();
        $this->storage = new SessionStorage($this->baseStorage);
    }

    /**
     *
     */
    public function test_exists_returns_false_if_storage_is_empty()
    {
        $this->assertFalse($this->storage->exists(), 'Storage is empty, so exists must return false');
    }

    /**
     *
     */
    public function test_exists_returns_true_if_storage_is_filled()
    {
        $this->baseStorage->attributes()['security.grant'] = new Grant('access_token', new DateTime(), 'refresh_token', 'Bearer');
        $this->assertTrue($this->storage->exists(), 'Storage is not empty, so exists must return true');
    }

    /**
     *
     */
    public function test_retrieve_returns_null_is_storage_is_empty()
    {
        $this->assertNull($this->storage->retrieve());
    }

    /**
     *
     */
    public function test_retrieve_returns_storage_content()
    {
        $grant = new Grant('access_token', new DateTime(), 'refresh_token', 'Bearer');
        $this->baseStorage->attributes()['security.grant'] = $grant;

        $this->assertSame($grant, $this->storage->retrieve());
    }

    /**
     *
     */
    public function test_store_sets_storage_content()
    {
        $grant = new Grant('access_token', new DateTime(), 'refresh_token', 'Bearer');
        $this->storage->store($grant);

        $this->assertSame($grant, $this->baseStorage->attributes()['security.grant']);
    }

    /**
     *
     */
    public function test_clear_removes_storage_content()
    {
        $grant = new Grant('access_token', new DateTime(), 'refresh_token', 'Bearer');
        $this->baseStorage->attributes()['security.grant'] = $grant;

        $this->storage->clear();

        $this->assertFalse(isset($this->baseStorage->attributes()['security.grant']));
    }
}