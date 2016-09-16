<?php

namespace Parroauth2\Client;

use Parroauth2\Client\Exception\ConnectionException;
use Parroauth2\Client\Storage\StorageInterface;
use Parroauth2\Client\Strategy\Authorization\AuthorizationStrategyInterface;

/**
 * Class AuthorizationClient
 *
 * @package Parroauth2\Client
 */
class AuthorizationClient
{
    /**
     * @var AuthorizationStrategyInterface
     */
    protected $authorizationStrategy;

    /**
     * @var StorageInterface
     */
    protected $storage;

    /**
     * AuthorizationClient constructor.
     * 
     * @param AuthorizationStrategyInterface $authorizationStrategy
     * @param StorageInterface $storage
     */
    public function __construct(AuthorizationStrategyInterface $authorizationStrategy, StorageInterface $storage)
    {
        $this->authorizationStrategy = $authorizationStrategy;
        $this->storage = $storage;
    }

    /**
     * @param $login
     * @param $password
     *
     * @return $this
     */
    public function login($login, $password)
    {
        $grant = $this->authorizationStrategy->token($login, $password);

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
            throw new ConnectionException('Client is not connected');
        }

        try {
            $grant = $this->authorizationStrategy->refresh($this->storage->retrieve());
            $this->storage->store($grant);

        } catch (ConnectionException $exception) {
            $this->storage->clear();
        }

        return $this;
    }

    /**
     * @return $this
     */
    public function logout()
    {
        if (!$this->storage->exists()) {
            return $this;
        }

        $this->authorizationStrategy->revoke($this->storage->retrieve());

        $this->storage->clear();

        return $this;
    }

    /**
     * @return Grant
     */
    public function getGrant()
    {
        if ($this->storage->exists()) {
            if ($this->storage->retrieve()->isExpired()) {
                $this->refresh();
            }

            return $this->storage->retrieve();
        }

        return null;
    }
}