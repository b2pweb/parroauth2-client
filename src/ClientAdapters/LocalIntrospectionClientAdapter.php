<?php

namespace Parroauth2\Client\ClientAdapters;

use Parroauth2\Client\Request;
use Parroauth2\Client\Response;
use Parroauth2\Client\Unserializer\UnserializerInterface;
use Parroauth2\Client\Exception\InvalidRequestException;

/**
 * LocalIntrospectionClientAdapter
 *
 * Introspect serialize access token.
 */
class LocalIntrospectionClientAdapter implements ClientAdapterInterface
{
    /**
     * @var UnserializerInterface
     */
    protected $unserializer;

    /**
     * the delegate adapter
     *
     * @var ClientAdapterInterface
     */
    protected $delegate;

    /**
     * LocalIntrospectionClientAdapter constructor.
     *
     * @param UnserializerInterface $unserializer
     * @param ClientAdapterInterface $delegate
     */
    public function __construct(UnserializerInterface $unserializer, ClientAdapterInterface $delegate = null)
    {
        $this->unserializer = $unserializer;
        $this->delegate = $delegate;
    }

    /**
     * {@inheritdoc}
     *
     * @throws InvalidRequestException
     */
    public function token(Request $request)
    {
        if ($this->delegate !== null) {
            return $this->delegate->token($request);
        }

        throw new InvalidRequestException('Access granting is not available');
    }

    /**
     * {@inheritdoc}
     *
     * @throws InvalidRequestException
     */
    public function getAuthorizationUri(Request $request)
    {
        if ($this->delegate !== null) {
            return $this->delegate->getAuthorizationUri($request);
        }

        throw new InvalidRequestException('Authorize procedure is not available');
    }

    /**
     * {@inheritdoc}
     */
    public function introspect(Request $request)
    {
        // L'introspection doit elle être sécurisée par client credentials ?
        // L'introspection est faite localement, et les informations décodées ne sortent pas du périmètre de l'application
        // La gestion des crédentials client n'a donc pas été implémenté.

        if ($request->attribute('token_type_hint') === 'refresh_token') {
            throw new InvalidRequestException('Refresh token introspect is not available. You can only introspect access tokens');
        }

        $token = $this->unserializer->unserialize($request->attribute('token'));

        if (null === $token) {
            return new Response(['active' => false]);
        }

        $expired = $token->getClaim('exp', 0);

        if ($expired >= 0 && $expired < time()) {
            return new Response(['active' => false]);
        }

        return new Response([
            'active'     => true,
            'scope'      => $token->getClaim('scope', ''),
            'client_id'  => $token->getClaim('aud', ''),
            'username'   => $token->getClaim('username', ''),
            'token_type' => $token->getClaim('token_type', ''),
            'exp'        => $expired,
            'iat'        => $token->getClaim('iat', 0),
            'nbf'        => $token->getClaim('nbf', 0),
            'sub'        => $token->getClaim('sub', ''),
            'aud'        => $token->getClaim('aud', ''),
            'iss'        => $token->getClaim('iss', ''),
            'jti'        => $token->getClaim('jti', ''),
            'metadata'   => $token->getClaim('metadata', []),
        ]);
    }

    /**
     * {@inheritdoc}
     *
     * @throws InvalidRequestException
     */
    public function revoke(Request $request)
    {
        if ($this->delegate !== null) {
            return $this->delegate->revoke($request);
        }

        throw new InvalidRequestException('Access revoking is not available');
    }

    /**
     * {@inheritdoc}
     *
     * @throws InvalidRequestException
     */
    public function userinfo(Request $request)
    {
        if ($this->delegate !== null) {
            return $this->delegate->userinfo($request);
        }

        throw new InvalidRequestException('Access to userinfo is not available');
    }
}