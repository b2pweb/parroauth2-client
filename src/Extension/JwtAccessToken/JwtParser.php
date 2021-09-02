<?php

namespace Parroauth2\Client\Extension\JwtAccessToken;

use Jose\Component\Core\JWKSet;
use Parroauth2\Client\Client;
use Parroauth2\Client\ClientInterface;
use Parroauth2\Client\Jwt\JwtDecoder;

/**
 * Simple parser using JwtDecoder
 * The key use for decode the JWT are stored into the 'access_token_jwk' option, or on the jwks
 *
 * @see JwtDecoder
 */
final class JwtParser implements JwtParserInterface
{
    /**
     * @var JwtDecoder
     */
    private $decoder;


    /**
     * JwtParser constructor.
     *
     * @param JwtDecoder|null $decoder
     */
    public function __construct(JwtDecoder $decoder = null)
    {
        $this->decoder = $decoder ?: new JwtDecoder();
    }

    /**
     * {@inheritdoc}
     */
    public function parse(string $jwt, ClientInterface $client): array
    {
        $keys = ($jwk = $client->option('access_token_jwk')) ? new JWKSet([$jwk]) : $client->keySet();

        return $this->decoder->decode($jwt, $keys)->payload();
    }
}
