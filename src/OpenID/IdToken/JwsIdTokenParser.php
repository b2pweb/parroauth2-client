<?php

namespace Parroauth2\Client\OpenID\IdToken;

use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use Parroauth2\Client\Client;
use Parroauth2\Client\Jwt\JWA;
use Parroauth2\Client\Jwt\JwtDecoder;

/**
 * Parse the ID Token in a JWS format
 */
final class JwsIdTokenParser implements IdTokenParserInterface
{
    /**
     * @var JwtDecoder
     */
    private $decoder;


    /**
     * JwsIdTokenParser constructor.
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
    public function parse(Client $client, string $idToken): IdToken
    {
        $keySet = $client->keySet();
        $decoder = $this->decoder;

        if ($supportedAlg = $client->option('id_token_signing_alg_values_supported')) {
            $decoder = $decoder->supportedAlgorithms($supportedAlg);
        }

        // Add client secret key to the set for HMAC signature
        // @see https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.10.1
        if ($client->secret() && $hmacAlgorithms = $decoder->jwa()->algorithmsByType(JWA::TYPE_HMAC)) {
            $keySet = $keySet->all();

            foreach ($hmacAlgorithms as $alg) {
                $keySet[] = JWKFactory::createFromSecret($client->secret(), ['alg' => $alg, 'use' => 'sig']);
            }

            $keySet = new JWKSet($keySet);
        }

        $jwt = $decoder->decode($idToken, $keySet);

        return new IdToken($idToken, $jwt->payload(), $jwt->headers());
    }
}
