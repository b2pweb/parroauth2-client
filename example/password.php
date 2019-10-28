<?php

/**
 * Client implementation for password grant type
 */

use Parroauth2\Client\ClientConfig;
use Parroauth2\Client\Provider\ProviderLoader;

require_once __DIR__.'/../vendor/autoload.php';

// Load the provider. Provide a storage is not required here : token is not stored
$loader = new ProviderLoader();
$provider = $loader->discover('http://192.168.0.139/~vquatrevieux/sso/s2pweb/oidc');

// Create the client
$client = $provider->client(
    (new ClientConfig('test_parroauth'))
        ->setSecret('tyiY2kmxhRC4T5TSEidXH9-a6K-8q3dQdn3OPAhtPNY')
);

// Get a token
var_dump($client->endPoints()->token()->password('vquatrevieux@b2pweb.com', '$vquatrevieux')->call());
