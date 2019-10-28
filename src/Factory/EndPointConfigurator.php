<?php

namespace Parroauth2\Client\Factory;

use Parroauth2\Client\Client;

/**
 * Configure endpoints for a client
 *
 * The configurator will check if the provider supports the endpoint, and then instantiate the endpoint
 */
final class EndPointConfigurator
{
    /**
     * @var array
     */
    private $endpoints;


    /**
     * EndPointConfigurator constructor.
     *
     * @param string[]|callable[] $endpoints Map of endpoint class name or factory, indexed by the endpoint name
     */
    public function __construct(array $endpoints)
    {
        $this->endpoints = $endpoints;
    }

    /**
     * Configure the endpoint on the client
     *
     * @param Client $client
     */
    public function configure(Client $client): void
    {
        foreach ($this->endpoints as $name => $endpoint) {
            if (!$client->provider()->supportsEndpoint($name)) {
                continue;
            }

            $endpoint = is_callable($endpoint) ? $endpoint($client) : new $endpoint($client);
            $client->endPoints()->add($endpoint);
        }
    }
}
