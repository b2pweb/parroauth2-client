<?php

namespace Parroauth2\Client\Extension;

use Base64Url\Base64Url;
use Parroauth2\Client\EndPoint\Authorization\AuthorizationEndPoint;
use Parroauth2\Client\EndPoint\EndPointTransformerTrait;
use Parroauth2\Client\EndPoint\Token\TokenEndPoint;

/**
 * Extension for enable Proof Key for Code Exchange
 * This extension may be register even if the provider do not supports PKCE
 *
 * Client options :
 * - code_challenge_method : "plain" | "S256" Configure the code challenge method. This option is case sensitive
 *
 * @see https://tools.ietf.org/html/rfc7636
 */
final class Pkce extends AbstractEndPointTransformerExtension
{
    use EndPointTransformerTrait;

    public const METHOD_PLAIN = 'plain';
    public const METHOD_S256 = 'S256';

    /**
     * {@inheritdoc}
     */
    public function onAuthorization(AuthorizationEndPoint $endPoint): AuthorizationEndPoint
    {
        $codeVerifier = Base64Url::encode(random_bytes(96));
        $this->client()->storage()->store('code_verifier', $codeVerifier);

        $codeChallengeMethod = $this->codeChallengeMethod();

        switch ($codeChallengeMethod) {
            case self::METHOD_PLAIN:
                $codeChallenge = $codeVerifier;
                break;

            case self::METHOD_S256:
                $codeChallenge = Base64Url::encode(hash('sha256', $codeVerifier, true));
                break;

            default:
                throw new \LogicException('Unsupported code challenge method ' . $codeChallengeMethod);
        }

        return $endPoint
            ->set('code_challenge', $codeChallenge)
            ->set('code_challenge_method', $codeChallengeMethod)
        ;
    }

    /**
     * {@inheritdoc}
     */
    public function onToken(TokenEndPoint $endPoint): TokenEndPoint
    {
        if ($codeVerifier = $this->client()->storage()->remove('code_verifier')) {
            return $endPoint->set('code_verifier', $codeVerifier);
        }

        return $endPoint;
    }

    /**
     * Get the supported code challenge method
     *
     * @return string
     */
    private function codeChallengeMethod(): string
    {
        if ($method = $this->client()->clientConfig()->option('code_challenge_method')) {
            return $method;
        }

        // Provider supports S256
        if (
            in_array(
                self::METHOD_S256,
                $this->client()->provider()->metadata('code_challenge_methods_supported', [self::METHOD_S256])
            )
        ) {
            return self::METHOD_S256;
        }

        return self::METHOD_PLAIN;
    }
}
