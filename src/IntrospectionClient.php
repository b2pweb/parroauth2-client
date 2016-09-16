<?php

namespace Parroauth2\Client;

use Parroauth2\Client\Exception\ConnectionException;
use Parroauth2\Client\Strategy\Introspection\IntrospectionStrategyInterface;

/**
 * Class IntrospectionClient
 *
 * @package Parroauth2\Client
 */
class IntrospectionClient
{
    /**
     * @var IntrospectionStrategyInterface
     */
    protected $introspectionStrategy;

    /**
     * Client constructor.
     *
     * @param IntrospectionStrategyInterface $introspectionStrategy
     */
    public function __construct(IntrospectionStrategyInterface $introspectionStrategy)
    {
        $this->introspectionStrategy = $introspectionStrategy;
    }

    /**
     * @param Grant|string $grant
     *
     * @return mixed
     *
     * @throws ConnectionException
     */
    public function introspect($grant)
    {
        if (!$grant || ($grant instanceof Grant && !$grant->getAccess())) {
            throw new ConnectionException('Client is not connected');
        }

        return $this->introspectionStrategy->introspect($grant);
    }
}