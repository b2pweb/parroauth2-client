<?php

namespace Parroauth2\Client\EndPoint;

/**
 * Implementation of the parameters for EndPointInterface
 *
 * @psalm-require-implements EndPointInterface
 */
trait EndPointParametersTrait
{
    /**
     * @var array
     * @readonly
     */
    private array $parameters = [];


    /**
     * {@inheritdoc}
     *
     * @psalm-mutation-free
     */
    public function get(string $parameter)
    {
        return $this->parameters[$parameter] ?? null;
    }

    /**
     * {@inheritdoc}
     *
     * @psalm-mutation-free
     */
    public function parameters(): array
    {
        return $this->parameters;
    }

    /**
     * {@inheritdoc}
     *
     * @param mixed $value
     *
     * @return static
     *
     * @psalm-mutation-free
     */
    public function set(string $parameter, mixed $value): self
    {
        $endpoint = clone $this;

        $endpoint->parameters[$parameter] = $value;

        return $endpoint;
    }
}
