<?php

namespace Parroauth2\Client\Extension\JwtAccessToken;

use Parroauth2\Client\Client;
use Parroauth2\Client\ClientInterface;

/**
 * Parse a JWT, and extract its claims
 */
interface JwtParserInterface
{
    /**
     * Parse the JWT
     *
     * @param string $jwt The JWT string
     * @param ClientInterface $client The client
     *
     * @return array The JWT claims
     *
     * @throws \InvalidArgumentException When the JWT is invalid
     */
    public function parse(string $jwt, ClientInterface $client): array;
}
