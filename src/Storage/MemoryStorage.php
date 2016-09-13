<?php

namespace Parroauth2\Client\Storage;

use Parroauth2\Client\Grant;

/**
 * Class MemoryStorage
 * 
 * @package Parroauth2\Client\Storage
 */
class MemoryStorage implements StorageInterface
{
    /**
     * @var Grant
     */
    protected $grant;

    /**
     * @inheritdoc
     */
    public function exists()
    {
        return null != $this->grant;
    }

    /**
     * @inheritdoc
     */
    public function retrieve()
    {
        if ($this->exists()) {
            return $this->grant;
        }

        return null;
    }

    /**
     * @inheritdoc
     */
    public function store($grant)
    {
        $this->grant = $grant;
    }

    /**
     * @inheritdoc
     */
    public function clear()
    {
        $this->grant = null;
    }
}