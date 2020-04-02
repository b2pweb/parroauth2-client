<?php

namespace Parroauth2\Client\EndPoint;

use Parroauth2\Client\EndPoint\Authorization\AuthorizationEndPoint;
use Parroauth2\Client\EndPoint\Introspection\IntrospectionEndPoint;
use Parroauth2\Client\EndPoint\Token\RevocationEndPoint;
use Parroauth2\Client\EndPoint\Token\TokenEndPoint;
use Parroauth2\Client\OpenID\EndPoint\EndSessionEndPoint;
use Parroauth2\Client\OpenID\EndPoint\Userinfo\UserinfoEndPoint;

/**
 * Add default methods implementations for EndPointTransformerInterface
 */
trait EndPointTransformerTrait
{
    /**
     * @see EndPointTransformerInterface::onEndPoint()
     */
    public function onEndPoint(EndPointInterface $endPoint): EndPointInterface
    {
        return $endPoint;
    }

    /**
     * @see EndPointTransformerInterface::onAuthorization()
     */
    public function onAuthorization(AuthorizationEndPoint $endPoint): AuthorizationEndPoint
    {
        return $endPoint;
    }

    /**
     * @see EndPointTransformerInterface::onToken()
     */
    public function onToken(TokenEndPoint $endPoint): TokenEndPoint
    {
        return $endPoint;
    }

    /**
     * @see EndPointTransformerInterface::onRevocation()
     */
    public function onRevocation(RevocationEndPoint $endPoint): RevocationEndPoint
    {
        return $endPoint;
    }

    /**
     * @see EndPointTransformerInterface::onIntrospection()
     */
    public function onIntrospection(IntrospectionEndPoint $endPoint): IntrospectionEndPoint
    {
        return $endPoint;
    }

    /**
     * @see EndPointTransformerInterface::onUserinfo()
     */
    public function onUserinfo(UserinfoEndPoint $endPoint): UserinfoEndPoint
    {
        return $endPoint;
    }

    /**
     * @see EndPointTransformerInterface::onEndSession()
     */
    public function onEndSession(EndSessionEndPoint $endPoint): EndSessionEndPoint
    {
        return $endPoint;
    }
}
