<?php

namespace Parroauth2\Client\Extension;

use Parroauth2\Client\ClientInterface;
use Parroauth2\Client\EndPoint\EndPointTransformerInterface;

/**
 * Implements extension for EndPointTransformer
 */
abstract class AbstractEndPointTransformerExtension implements ExtensionInterface, EndPointTransformerInterface
{
    private ?ClientInterface $client = null;

    /**
     * {@inheritdoc}
     */
    final public function configure(ClientInterface $client): void
    {
        $extension = $this->client === null ? $this : clone $this;
        $extension->client = $client;

        $client->endPoints()->register($extension);
    }

    /**
     * Get the configured client
     *
     * @return ClientInterface
     *
     * @psalm-mutation-free
     *
     * @psalm-suppress InvalidNullableReturnType
     * @psalm-suppress NullableReturnStatement
     */
    final protected function client(): ClientInterface
    {
        return $this->client;
    }
}
