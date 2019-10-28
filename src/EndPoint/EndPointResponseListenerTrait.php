<?php

namespace Parroauth2\Client\EndPoint;

/**
 * Add response listener handling on endpoint
 */
trait EndPointResponseListenerTrait
{
    /**
     * @var callable[]
     */
    private $responseListeners = [];


    /**
     * Subscribe for the endpoint response
     * Listener prototype : function ($response): void
     *
     * @param callable $listener The listener
     *
     * @return static
     */
    public function onResponse(callable $listener): self
    {
        $endpoint = clone $this;
        $endpoint->responseListeners[] = $listener;

        return $endpoint;
    }

    /**
     * Call all response listeners
     *
     * @param mixed $response
     */
    protected function callResponseListeners($response): void
    {
        foreach ($this->responseListeners as $listener) {
            $listener($response);
        }
    }
}
