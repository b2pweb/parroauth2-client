<?php

namespace Parroauth2\Client\Strategy\Authorization;

use Parroauth2\Client\Grant;

/**
 * Interface AuthorizationStrategyInterface
 * 
 * @package Parroauth2\Client\Strategy\Authorization
 */
interface AuthorizationStrategyInterface
{
    /**
     * @param string $login
     * @param string $password
     *
     * @return Grant
     */
    public function token($login, $password);

    /**
     * @param Grant|string $grant
     *
     * @return Grant
     */
    public function refresh($grant);

    /**
     * @param Grant|string $grant
     *
     * @return $this
     */
    public function revoke($grant);
}