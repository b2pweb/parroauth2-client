<?php

namespace Parroauth2\Client;

use Parroauth2\Client\Exception\ConnectionException;
use Parroauth2\Client\Storage\StorageInterface;
use Parroauth2\Client\Strategy\Authorization\AuthorizationStrategyInterface;
use Parroauth2\Client\Strategy\Introspection\IntrospectionStrategyInterface;

/**
 * Class Client
 *
 * @package Parroauth2\Client
 */
class Client implements AuthorizationClientInterface, IntrospectionClientInterface
{
    /**
     * @var StorageInterface
     */
    protected $storage;

    /**
     * @var AuthorizationStrategyInterface
     */
    protected $authorizationStrategy;

    /**
     * @var IntrospectionStrategyInterface
     */
    protected $introspectionStrategy;

    /**
     * Client constructor.
     *
     * @param StorageInterface $storage
     */
    public function __construct(StorageInterface $storage)
    {
        $this->storage = $storage;
    }

    /**
     * @param AuthorizationStrategyInterface $authorizationStrategy
     * 
     * @return $this
     */
    public function setAuthorizationStrategy(AuthorizationStrategyInterface $authorizationStrategy)
    {
        $this->authorizationStrategy = $authorizationStrategy;
        
        return $this;
    }

    /**
     * @return AuthorizationStrategyInterface
     */
    public function getAuthorizationStrategy()
    {
        return $this->authorizationStrategy;
    }

    /**
     * @param IntrospectionStrategyInterface $introspectionStrategy
     *
     * @return $this
     */
    public function setIntrospectionStrategy(IntrospectionStrategyInterface $introspectionStrategy)
    {
        $this->introspectionStrategy = $introspectionStrategy;

        return $this;
    }

    /**
     * @return IntrospectionStrategyInterface
     */
    public function getIntrospectionStrategy()
    {
        return $this->introspectionStrategy;
    }

    /**
     * {@inheritdoc}
     */
    public function login($login, $password)
    {
        $grant = $this->authorizationStrategy()->token($login, $password);

        $this->storage->store($grant);

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function refresh()
    {
        if (!$this->storage->exists()) {
            throw new ConnectionException('Client is not connected');
        }

        try {
            $grant = $this->authorizationStrategy()->refresh($this->storage->retrieve());
            $this->storage->store($grant);

        } catch (ConnectionException $exception) {
            $this->storage->clear();
        }

        return $this;
    }

    /**
     * {@inheritdoc}
     *
     * @throws ConnectionException
     */
    public function introspect()
    {
        $grant = $this->getGrant();

        if (!$grant) {
            throw new ConnectionException('Client is not connected');
        }

        return $this->introspectionStrategy()->introspect($grant);
    }

    /**
     * @return {@inheritdoc}
     */
    public function logout()
    {
        if (!$this->storage->exists()) {
            return $this;
        }

        $this->authorizationStrategy()->revoke($this->storage->retrieve());

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

    /**
     * @return AuthorizationStrategyInterface
     *
     * @throws \Exception
     */
    protected function authorizationStrategy()
    {
        if (!$this->authorizationStrategy) {
            throw new \Exception('Error!');
        }

        return $this->authorizationStrategy;
    }

    /**
     * @return IntrospectionStrategyInterface
     *
     * @throws \Exception
     */
    protected function introspectionStrategy()
    {
        if (!$this->introspectionStrategy) {
            throw new \Exception('Error!');
        }

        return $this->introspectionStrategy;
    }
}