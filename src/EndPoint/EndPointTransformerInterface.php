<?php

namespace Parroauth2\Client\EndPoint;

use Parroauth2\Client\EndPoint\Authorization\AuthorizationEndPoint;
use Parroauth2\Client\EndPoint\Introspection\IntrospectionEndPoint;
use Parroauth2\Client\EndPoint\Token\RevocationEndPoint;
use Parroauth2\Client\EndPoint\Token\TokenEndPoint;
use Parroauth2\Client\OpenID\EndPoint\EndSessionEndPoint;
use Parroauth2\Client\OpenID\EndPoint\Userinfo\UserinfoEndPoint;

/**
 * Transform an endpoint for adding extra parameters
 */
interface EndPointTransformerInterface
{
    /**
     * Transform a generic endpoint
     *
     * @param T $endPoint
     *
     * @return EndPointInterface
     * @psalm-return T
     *
     * @template T as EndPointInterface
     */
    public function onEndPoint(EndPointInterface $endPoint): EndPointInterface;

    /**
     * Transform the authorization endpoint
     *
     * @param T $endPoint
     *
     * @return AuthorizationEndPoint
     * @psalm-return T
     *
     * @template T as AuthorizationEndPoint
     */
    public function onAuthorization(AuthorizationEndPoint $endPoint): AuthorizationEndPoint;

    /**
     * Transform the token endpoint
     *
     * @param T $endPoint
     *
     * @return TokenEndPoint
     * @psalm-return T
     *
     * @template T as TokenEndPoint
     */
    public function onToken(TokenEndPoint $endPoint): TokenEndPoint;

    /**
     * Transform the revocation endpoint
     *
     * @param T $endPoint
     *
     * @return RevocationEndPoint
     * @psalm-return T
     *
     * @template T as RevocationEndPoint
     */
    public function onRevocation(RevocationEndPoint $endPoint): RevocationEndPoint;

    /**
     * Transform the introspection endpoint
     *
     * @param T $endPoint
     *
     * @return IntrospectionEndPoint
     * @psalm-return T
     *
     * @template T as IntrospectionEndPoint
     */
    public function onIntrospection(IntrospectionEndPoint $endPoint): IntrospectionEndPoint;

    /**
     * Transform the introspection endpoint
     *
     * @param T $endPoint
     *
     * @return UserinfoEndPoint
     * @psalm-return T
     *
     * @template T as UserinfoEndPoint
     */
    public function onUserinfo(UserinfoEndPoint $endPoint): UserinfoEndPoint;

    /**
     * Transform the end session endpoint
     *
     * @param T $endPoint
     *
     * @return EndSessionEndPoint
     * @psalm-return T
     *
     * @template T as EndSessionEndPoint
     */
    public function onEndSession(EndSessionEndPoint $endPoint): EndSessionEndPoint;
}
