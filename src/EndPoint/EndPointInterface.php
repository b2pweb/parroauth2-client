<?php

namespace Parroauth2\Client\EndPoint;

/**
 * Define a protocol endpoint
 * The endpoint consist of an URI on the Authorization provider
 *
 * The implementation must be immutable, so all modifier methods will return a new instance of the endpoint
 */
interface EndPointInterface
{
    /**
     * Get the endpoint name
     * The name is defined as parameter of the server metadata
     *
     * @return string
     *
     * @psalm-mutation-free
     */
    public function name(): string;

    /**
     * Add a parameter to the endpoint
     *
     * @param string $parameter
     * @param mixed $value
     *
     * @return static
     *
     * @psalm-mutation-free
     */
    public function set(string $parameter, $value);

    /**
     * Get an endpoint parameter
     *
     * @param string $parameter
     *
     * @return mixed
     *
     * @psalm-mutation-free
     */
    public function get(string $parameter);

    /**
     * Get all endpoint parameters
     *
     * @return array
     *
     * @psalm-mutation-free
     */
    public function parameters(): array;

    /**
     * Apply a transformer on the endpoint, and return the transformed value
     * The transformed value must keep the type of the endpoint
     *
     * @param EndPointTransformerInterface $transformer
     *
     * @return static
     */
    public function apply(EndPointTransformerInterface $transformer);
}
