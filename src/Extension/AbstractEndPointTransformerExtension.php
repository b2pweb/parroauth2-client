<?php

namespace Parroauth2\Client\Extension;

use Parroauth2\Client\Client;
use Parroauth2\Client\EndPoint\EndPointTransformerInterface;

/**
 * Implements extension for EndPointTransformer
 */
abstract class AbstractEndPointTransformerExtension implements ExtensionInterface, EndPointTransformerInterface
{
    /**
     * @var Client
     */
    private $client;

    /**
     * {@inheritdoc}
     */
    final public function configure(Client $client): void
    {
        $extension = $this->client === null ? $this : clone $this;
        $extension->client = $client;

        $client->endPoints()->register($extension);
    }

    /**
     * Get the configured client
     *
     * @return Client
     */
    final protected function client(): Client
    {
        return $this->client;
    }
}
