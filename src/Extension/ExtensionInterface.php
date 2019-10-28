<?php

namespace Parroauth2\Client\Extension;

use Parroauth2\Client\Client;

/**
 * Base type for extension
 * Permit to extends or overrides client functionalities
 *
 * The extension must be registered using Client::register()
 * An extension instance may be registered to multiple clients
 */
interface ExtensionInterface
{
    /**
     * Configure the client for enable the extension
     *
     * @param Client $client
     */
    public function configure(Client $client): void;
}
