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
 *
 * @psalm-require-implements EndPointTransformerInterface
 */
trait EndPointTransformerTrait
{
    /**
     * {@inheritdoc}
     *
     * @see EndPointTransformerInterface::onEndPoint()
     * @psalm-suppress ImplementedReturnTypeMismatch
     */
    public function onEndPoint(EndPointInterface $endPoint): EndPointInterface
    {
        return $endPoint;
    }

    /**
     * {@inheritdoc}
     *
     * @see EndPointTransformerInterface::onAuthorization()
     * @psalm-suppress ImplementedReturnTypeMismatch
     */
    public function onAuthorization(AuthorizationEndPoint $endPoint): AuthorizationEndPoint
    {
        return $endPoint;
    }

    /**
     * {@inheritdoc}
     *
     * @see EndPointTransformerInterface::onToken()
     * @psalm-suppress ImplementedReturnTypeMismatch
     */
    public function onToken(TokenEndPoint $endPoint): TokenEndPoint
    {
        return $endPoint;
    }

    /**
     * {@inheritdoc}
     *
     * @see EndPointTransformerInterface::onRevocation()
     * @psalm-suppress ImplementedReturnTypeMismatch
     */
    public function onRevocation(RevocationEndPoint $endPoint): RevocationEndPoint
    {
        return $endPoint;
    }

    /**
     * {@inheritdoc}
     *
     * @see EndPointTransformerInterface::onIntrospection()
     * @psalm-suppress ImplementedReturnTypeMismatch
     */
    public function onIntrospection(IntrospectionEndPoint $endPoint): IntrospectionEndPoint
    {
        return $endPoint;
    }

    /**
     * {@inheritdoc}
     *
     * @see EndPointTransformerInterface::onUserinfo()
     * @psalm-suppress ImplementedReturnTypeMismatch
     */
    public function onUserinfo(UserinfoEndPoint $endPoint): UserinfoEndPoint
    {
        return $endPoint;
    }

    /**
     * {@inheritdoc}
     *
     * @see EndPointTransformerInterface::onEndSession()
     * @psalm-suppress ImplementedReturnTypeMismatch
     */
    public function onEndSession(EndSessionEndPoint $endPoint): EndSessionEndPoint
    {
        return $endPoint;
    }
}
