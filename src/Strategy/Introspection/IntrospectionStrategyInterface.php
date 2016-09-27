<?php

namespace Parroauth2\Client\Strategy\Introspection;

use Parroauth2\Client\Introspection;

/**
 * Interface IntrospectionStrategyInterface
 *
 * @package Parroauth2\Client\Strategy\Introspection
 */
interface IntrospectionStrategyInterface
{
    /**
     * @param string $token
     * @param string $type
     *
     * @return Introspection
     */
    public function introspect($token, $type = '');
}