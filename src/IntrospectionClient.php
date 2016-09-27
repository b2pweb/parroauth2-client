<?php

namespace Parroauth2\Client;

use Parroauth2\Client\Exception\InternalErrorException;
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
     * @param Grant|string $token
     * @param string $type
     *
     * @return Introspection
     *
     * @throws InternalErrorException
     */
    public function introspect($token, $type = '')
    {
        if ($token instanceof Grant) {
            $token = $token->getAccess();
            $type = 'access_token';
        }

        if (!$token) {
            throw new InternalErrorException('Unable to introspect empty token', 500);
        }

        return $this->introspectionStrategy->introspect($token, $type);
    }
}