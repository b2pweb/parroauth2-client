<?php

namespace Parroauth2\Client\Adapter;

use Parroauth2\Client\Grant;

/**
 * Interface AdapterInterface
 * 
 * @package Parroauth2\Client\Adapter
 */
interface AdapterInterface
{
    /**
     * @param string $username
     * @param string $password
     *
     * @return Grant
     */
    public function token($username, $password);

    /**
     * @param Grant|string $token
     *
     * @return Grant
     */
    public function refresh($token);

    /**
     * @param Grant|string $token
     *
     * @return array
     */
    public function userinfo($token);

    /**
     * @param Grant|string $token
     *
     * @return array
     */
    public function introspect($token);

    /**
     * @param Grant|string $token
     *
     * @return $this
     */
    public function revoke($token);
}