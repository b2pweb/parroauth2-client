<?php

namespace Parroauth2\Client\EndPoint;

/**
 * Add response listener handling on endpoint
 *
 * @template T as object
 */
trait EndPointResponseListenerTrait
{
    /**
     * @var list<callable(T):void>
     * @readonly
     */
    private $responseListeners = [];


    /**
     * {@inheritdoc}
     *
     * @param callable(T):void $listener
     *
     * @return static
     * @psalm-mutation-free
     */
    public function onResponse(callable $listener): CallableEndPointInterface
    {
        $endpoint = clone $this;
        $endpoint->responseListeners[] = $listener;

        return $endpoint;
    }

    /**
     * Call all response listeners
     *
     * @param T $response
     */
    protected function callResponseListeners($response): void
    {
        foreach ($this->responseListeners as $listener) {
            /** @psalm-suppress ArgumentTypeCoercion */
            $listener($response);
        }
    }
}
