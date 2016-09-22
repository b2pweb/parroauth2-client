<?php

namespace Parroauth2\Client;

use Parroauth2\Client\Exception\ConnectionException;
use Parroauth2\Client\Exception\InternalErrorException;
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
     * AuthorizationClient constructor.
     * 
     * @param AuthorizationStrategyInterface $authorizationStrategy
     */
    public function __construct(AuthorizationStrategyInterface $authorizationStrategy)
    {
        $this->authorizationStrategy = $authorizationStrategy;
    }

    /**
     * @param string $login
     * @param string $password
     *
     * @return $this
     */
    public function login($login, $password)
    {
        return $this->authorizationStrategy->token($login, $password);
    }

    /**
     * @param Grant|string $token
     * 
     * @return $this
     * 
     * @throws InternalErrorException
     * @throws ConnectionException
     */
    public function refresh($token)
    {
        if ($token instanceof Grant) {
            $token = $token->getRefresh();
        }

        if (!$token) {
            throw new InternalErrorException('Unable to refresh empty token', 500);
        }

        return $this->authorizationStrategy->refresh($token);
    }

    /**
     * @param Grant|string $token
     */
    public function logout($token)
    {
        if ($token instanceof Grant) {
            $token = $token->getAccess();
        }

        if (!$token) {
            return;
        }

        $this->authorizationStrategy->revoke($token);
    }
}