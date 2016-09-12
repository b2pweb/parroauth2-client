<?php

namespace Parroauth2\Client;

use Bdf\Session\Storage\SessionStorageInterface;
use Parroauth2\Client\Exception\ConnectionException;

/**
 * Class Service
 *
 * @package Parroauth2\Client
 */
class Service
{
    /**
     * @var SessionStorageInterface
     */
    protected $storage;

    /**
     * Service constructor.
     *
     * @param Client $client
     * @param SessionStorageInterface $storage
     */
    public function __construct(Client $client, SessionStorageInterface $storage)
    {
        $this->client = $client;
        $this->storage = $storage;
    }

    /**
     * @param Token $token
     *
     * @return $this
     */
    public function setToken(Token $token = null)
    {
        $this->storage->attributes()['security_token'] = $token;

        return $this;
    }

    /**
     * @return Token
     */
    public function getToken()
    {
        if (!isset($this->storage->attributes()['security_token'])) {
            return null;
        }

        return $this->storage->attributes()['security_token'];
    }

    /**
     * @param string $username
     * @param string $password
     *
     * @return $this
     */
    public function login($username, $password)
    {
        $token = $this->client->token($username, $password);

        $this->setToken($token);

        return $this;
    }

    /**
     * @return $this
     *
     * @throws ConnectionException
     */
    public function refresh()
    {
        if (!($token = $this->getToken())) {
            throw new ConnectionException('Not connected to service');
        }

        try {
            $token = $this->client->refresh($token);
            $this->setToken($token);

        } catch (ConnectionException $exception) {
            $this->setToken(null);
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
        if (!($token = $this->getToken())) {
            throw new ConnectionException('Not connected to service');
        }

        return $this->client->userinfo($token);
    }

    /**
     * @return array
     *
     * @throws ConnectionException
     */
    public function introspect()
    {
        if (!($token = $this->getToken())) {
            throw new ConnectionException('Not connected to service');
        }

        return $this->client->introspect($token);
    }

    /**
     * @return $this
     */
    public function logout()
    {
        if (!($token = $this->getToken())) {
            return $this;
        }

        $this->client->revoke($token);

        $this->setToken(null);

        return $this;
    }
}