<?php

namespace Parroauth2\Client\Factory;

use Parroauth2\Client\Client;
use Parroauth2\Client\ClientConfig;
use Parroauth2\Client\Provider\Provider;
use Parroauth2\Client\Provider\ProviderInterface;

/**
 * Factory for clients
 */
interface ClientFactoryInterface
{
    /**
     * Create a client for the given provider and configuration
     *
     * @param ProviderInterface $provider
     * @param ClientConfig $config
     *
     * @return Client
     */
    public function create(ProviderInterface $provider, ClientConfig $config): Client;
}
