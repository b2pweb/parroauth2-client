<?php

namespace Parroauth2\Client;

/**
 * Interface AuthorizationClientInterface
 * 
 * @package Parroauth2\Client
 */
interface AuthorizationClientInterface
{
    /**
     * @param $login
     * @param $password
     *
     * @return $this
     */
    public function login($login, $password);

    /**
     * @return $this
     */
    public function refresh();

    /**
     * @return $this
     */
    public function logout();
}