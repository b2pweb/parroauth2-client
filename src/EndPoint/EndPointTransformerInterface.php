<?php

namespace Parroauth2\Client\EndPoint;

use Parroauth2\Client\EndPoint\Authorization\AuthorizationEndPoint;
use Parroauth2\Client\EndPoint\Introspection\IntrospectionEndPoint;
use Parroauth2\Client\EndPoint\Token\RevocationEndPoint;
use Parroauth2\Client\EndPoint\Token\TokenEndPoint;
use Parroauth2\Client\OpenID\EndPoint\Userinfo\UserinfoEndPoint;

/**
 * Transform an endpoint for adding extra parameters
 */
interface EndPointTransformerInterface
{
    /**
     * Transform a generic endpoint
     *
     * @param EndPointInterface $endPoint
     *
     * @return EndPointInterface
     */
    public function onEndPoint(EndPointInterface $endPoint): EndPointInterface;

    /**
     * Transform the authorization endpoint
     *
     * @param AuthorizationEndPoint $endPoint
     *
     * @return AuthorizationEndPoint
     */
    public function onAuthorization(AuthorizationEndPoint $endPoint): AuthorizationEndPoint;

    /**
     * Transform the token endpoint
     *
     * @param TokenEndPoint $endPoint
     *
     * @return TokenEndPoint
     */
    public function onToken(TokenEndPoint $endPoint): TokenEndPoint;

    /**
     * Transform the revocation endpoint
     *
     * @param RevocationEndPoint $endPoint
     *
     * @return RevocationEndPoint
     */
    public function onRevocation(RevocationEndPoint $endPoint): RevocationEndPoint;

    /**
     * Transform the introspection endpoint
     *
     * @param IntrospectionEndPoint $endPoint
     *
     * @return IntrospectionEndPoint
     */
    public function onIntrospection(IntrospectionEndPoint $endPoint): IntrospectionEndPoint;

    /**
     * Transform the introspection endpoint
     *
     * @param UserinfoEndPoint $endPoint
     *
     * @return UserinfoEndPoint
     */
    public function onUserinfo(UserinfoEndPoint $endPoint): UserinfoEndPoint;
}
