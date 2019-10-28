<?php

namespace Parroauth2\Client\EndPoint;

/**
 * Implementation of the parameters for EndPointInterface
 */
trait EndPointParametersTrait
{
    /**
     * @var array
     */
    private $parameters = [];


    /**
     * {@inheritdoc}
     */
    public function get(string $parameter)
    {
        return $this->parameters[$parameter] ?? null;
    }

    /**
     * {@inheritdoc}
     */
    public function parameters(): array
    {
        return $this->parameters;
    }

    /**
     * {@inheritdoc}
     */
    public function set(string $parameter, $value): self
    {
        $endpoint = clone $this;

        $endpoint->parameters[$parameter] = $value;

        return $endpoint;
    }
}
