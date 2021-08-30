<?php

namespace Parroauth2\Client\EndPoint;

use Http\Client\Exception;
use Parroauth2\Client\Exception\Parroauth2Exception;

/**
 * Base type for Webservice / callable endpoints
 *
 * Those endpoints should have a response, and response transformers
 *
 * @template T as object
 */
interface CallableEndPointInterface extends EndPointInterface
{
    /**
     * Call the endpoint
     *
     * @return T The endpoint response
     *
     * @throws Parroauth2Exception When an error occurs during execution
     * @throws Exception
     *
     * @psalm-suppress InvalidThrow
     */
    public function call();

    /**
     * Subscribe for the endpoint response
     * Listener prototype : function (T $response): void
     *
     * @param callable(T):void $listener The listener
     *
     * @return static A new instance with the configured listener
     *
     * @psalm-mutation-free
     */
    public function onResponse(callable $listener): self;
}
