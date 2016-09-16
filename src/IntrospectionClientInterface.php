<?php

namespace Parroauth2\Client;

/**
 * Interface IntrospectionClientInterface
 *
 * @package Parroauth2\Client
 */
interface IntrospectionClientInterface
{
    /**
     * @return mixed
     */
    public function introspect();
}