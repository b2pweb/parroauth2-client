<?php

namespace Parroauth2\Client;

use Parroauth2\Client\Adapter\AdapterInterface;
use Parroauth2\Client\Exception\ConnectionException;
use Parroauth2\Client\Storage\StorageInterface;

/**
 * Class Client
 *
 * @package Parroauth2\Client
 */
class Client
{
    /**
     * @var StorageInterface
     */
    protected $storage;

    /**
     * Client constructor.
     *
     * @param AdapterInterface $adapter
     * @param StorageInterface $storage
     */
    public function __construct(AdapterInterface $adapter, StorageInterface $storage)
    {
        $this->adapter = $adapter;
        $this->storage = $storage;
    }

    /**
     * @todo Refresh if expired
     * 
     * @return string
     */
    public function getAccessToken()
    {
        if ($this->storage->exists()) {
            if ($this->storage->retrieve()->isExpired()) {
                $this->refresh();
            }

            return $this->storage->retrieve()->getAccess();
        }

        return '';
    }

    /**
     * @param string $username
     * @param string $password
     *
     * @return $this
     */
    public function login($username, $password)
    {
        $grant = $this->adapter->token($username, $password);

        $this->storage->store($grant);

        return $this;
    }

    /**
     * @return $this
     *
     * @throws ConnectionException
     */
    public function refresh()
    {
        if (!$this->storage->exists()) {
            throw new ConnectionException('Not connected to service');
        }

        try {
            $grant = $this->adapter->refresh($this->storage->retrieve());
            $this->storage->store($grant);

        } catch (ConnectionException $exception) {
            $this->storage->clear();
        }

        return $this;
    }

    /**
     * @return array
     *
     * @throws ConnectionException
     */
    public function userinfo()
    {
        if (!$this->storage->exists()) {
            throw new ConnectionException('Not connected to service');
        }

        return $this->adapter->userinfo($this->storage->retrieve());
    }

    /**
     * @return array
     *
     * @throws ConnectionException
     */
    public function introspect()
    {
        if (!$this->storage->exists()) {
            throw new ConnectionException('Not connected to service');
        }

        return $this->adapter->introspect($this->storage->retrieve());
    }

    /**
     * @return $this
     */
    public function logout()
    {
        if (!$this->storage->exists()) {
            return $this;
        }

        $this->adapter->revoke($this->storage->retrieve());

        $this->storage->clear();

        return $this;
    }
}