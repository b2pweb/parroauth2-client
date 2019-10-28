<?php

namespace Parroauth2\Client\OpenID\IdToken;

use Base64Url\Base64Url;
use Parroauth2\Client\Jwt\JWA;

/**
 * Utility class for compute and check the at_hash claim of the ID Token
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
 */
final class AccessTokenHash
{
    /**
     * @var JWA
     */
    private $jwa;

    /**
     * AccessTokenHash constructor.
     *
     * @param JWA $jwa
     */
    public function __construct(JWA $jwa = null)
    {
        $this->jwa = $jwa ?: new JWA();
    }

    /**
     * Compute the at_hash claim value
     *
     * @param string $accessToken The access token string
     * @param string $alg The "alg" header value of the ID Token's header
     *
     * @return string
     */
    public function compute(string $accessToken, string $alg): string
    {
        $algo = $this->jwa->hashAlgorithm($alg);

        $hash = hash($algo, $accessToken, true);
        $hash = substr($hash, 0, strlen($hash) / 2);

        return Base64Url::encode($hash);
    }

    /**
     * Check if the access token hash stored into the ID Token corresponds with the access token
     * If the ID Token has no claim at_hash, this method will always return true
     *
     * @param IdToken $idToken The ID Token
     * @param string $accessToken The access token string
     *
     * @return bool
     */
    public function check(IdToken $idToken, string $accessToken): bool
    {
        if (!$idToken->accessTokenHash()) {
            return true;
        }

        return hash_equals($this->compute($accessToken, $idToken->header('alg')), $idToken->accessTokenHash());
    }
}
