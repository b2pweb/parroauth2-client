<?php

namespace Parroauth2\Client\Storage;

use Bdf\Session\Storage\SessionStorageInterface;

/**
 * Class SessionStorage
 *
 * @package Parroauth2\Client\Storage
 */
class SessionStorage implements StorageInterface
{
    /**
     * @var SessionStorageInterface
     */
    protected $storage;

    /**
     * SessionStorage constructor.
     * 
     * @param SessionStorageInterface $storage
     */
    public function __construct(SessionStorageInterface $storage)
    {
        $this->storage = $storage;
    }

    /**
     * @inheritdoc
     */
    public function exists()
    {
        return isset($this->storage->attributes()['security.grant']);
    }

    /**
     * @inheritdoc
     */
    public function retrieve()
    {
        if ($this->exists()) {
            return $this->storage->attributes()['security.grant'];
        }

        return null;
    }

    /**
     * @inheritdoc
     */
    public function store($grant)
    {
        $this->storage->attributes()['security.grant'] = $grant;
    }

    /**
     * @inheritdoc
     */
    public function clear()
    {
        unset($this->storage->attributes()['security.grant']);
    }
}