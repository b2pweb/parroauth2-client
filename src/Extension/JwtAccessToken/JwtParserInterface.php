<?php

namespace Parroauth2\Client\Extension\JwtAccessToken;

use Parroauth2\Client\Client;

/**
 * Parse a JWT, and extract its claims
 */
interface JwtParserInterface
{
    /**
     * Parse the JWT
     *
     * @param string $jwt The JWT string
     * @param Client $client The client
     *
     * @return array The JWT claims
     *
     * @throws \InvalidArgumentException When the JWT is invalid
     */
    public function parse(string $jwt, Client $client): array;
}
