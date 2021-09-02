<?php

namespace Parroauth2\Client\Extension;

use Parroauth2\Client\EndPoint\EndPointTransformerTrait;
use Parroauth2\Client\EndPoint\Introspection\IntrospectionEndPoint;
use Parroauth2\Client\EndPoint\Introspection\IntrospectionResponse;
use Parroauth2\Client\EndPoint\Token\RevocationEndPoint;
use Parroauth2\Client\EndPoint\Token\TokenEndPoint;
use Parroauth2\Client\EndPoint\Token\TokenResponse;
use Parroauth2\Client\OpenID\EndPoint\EndSessionEndPoint;
use Parroauth2\Client\OpenID\EndPoint\Token\TokenResponse as OpenIdTokenResponse;
use Parroauth2\Client\OpenID\EndPoint\Userinfo\UserinfoEndPoint;

/**
 * Extension for store and use access tokens
 *
 * Listen for the token endpoint response for store and update the token
 *
 * Add the access token on endpoints :
 * - userinfo
 * - introspection
 * - revocation
 */
final class TokenStorage extends AbstractEndPointTransformerExtension
{
    use EndPointTransformerTrait;

    /**
     * {@inheritdoc}
     */
    public function onToken(TokenEndPoint $endPoint): TokenEndPoint
    {
        return $endPoint->onResponse(function (TokenResponse $response) {
            $this->client()->storage()->store(self::class, $response);
        });
    }

    /**
     * {@inheritdoc}
     */
    public function onUserinfo(UserinfoEndPoint $endPoint): UserinfoEndPoint
    {
        return $this->expired() ? $endPoint : $endPoint->token($this->token()->accessToken());
    }

    /**
     * {@inheritdoc}
     */
    public function onIntrospection(IntrospectionEndPoint $endPoint): IntrospectionEndPoint
    {
        return $this->expired()
            ? $endPoint
            : $endPoint->accessToken($this->token()->accessToken())
                ->onResponse(function (IntrospectionResponse $response) {
                    if (!$response->active()) {
                        $this->clear();
                    }
                })
        ;
    }

    /**
     * {@inheritdoc}
     */
    public function onRevocation(RevocationEndPoint $endPoint): RevocationEndPoint
    {
        return $this->expired()
            ? $endPoint
            : $endPoint->accessToken($this->token()->accessToken())->onResponse([$this, 'clear'])
        ;
    }

    /**
     * {@inheritdoc}
     */
    public function onEndSession(EndSessionEndPoint $endPoint): EndSessionEndPoint
    {
        $token = $this->token();

        if (!$token instanceof OpenIdTokenResponse || !$token->idToken()) {
            return $endPoint;
        }

        return $endPoint->idToken($token->idToken());
    }

    /**
     * Get the stored token
     *
     * @return TokenResponse|null
     */
    public function token(): ?TokenResponse
    {
        return $this->client()->storage()->has(self::class) ? $this->client()->storage()->retrieve(self::class) : null;
    }

    /**
     * Check if the stored token is not available or expired
     *
     * @return bool
     *
     * @psalm-assert-if-false TokenResponse $this->token()
     */
    public function expired(): bool
    {
        /** @psalm-suppress PossiblyNullReference */
        return !$this->client()->storage()->has(self::class) || $this->token()->expired();
    }

    /**
     * Remove the stored token
     */
    public function clear(): void
    {
        $this->client()->storage()->remove(self::class);
    }
}
