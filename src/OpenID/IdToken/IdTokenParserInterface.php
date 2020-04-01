<?php

namespace Parroauth2\Client\OpenID\IdToken;

use Parroauth2\Client\Client;
use Parroauth2\Client\ClientInterface;

/**
 * Parse the ID Token
 */
interface IdTokenParserInterface
{
    /**
     * Parse the ID Token and validate the signature
     * Note: The claims are not checked here
     *
     * @param ClientInterface $client
     * @param string $idToken The raw ID Token
     *
     * @return IdToken
     */
    public function parse(ClientInterface $client, string $idToken): IdToken;
}
