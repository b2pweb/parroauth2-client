<?php

namespace Parroauth2\Client\Strategy\Introspection;

use Parroauth2\Client\Grant;

/**
 * Interface IntrospectionStrategyInterface
 *
 * @package Parroauth2\Client\Strategy\Introspection
 */
interface IntrospectionStrategyInterface
{
    /**
     * @param Grant|string $grant
     *
     * @return mixed
     */
    public function introspect($grant);
}