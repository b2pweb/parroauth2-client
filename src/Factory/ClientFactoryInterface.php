<?php

namespace Parroauth2\Client\Factory;

use Parroauth2\Client\Client;
use Parroauth2\Client\ClientConfig;
use Parroauth2\Client\Provider\Provider;

/**
 * Factory for clients
 */
interface ClientFactoryInterface
{
    /**
     * Create a client for the given provider and configuration
     *
     * @param Provider $provider
     * @param ClientConfig $config
     *
     * @return Client
     */
    public function create(Provider $provider, ClientConfig $config): Client;
}
