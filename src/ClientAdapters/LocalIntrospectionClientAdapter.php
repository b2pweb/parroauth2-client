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

//        if ($request->credentials() === null) {
//            return new Response(['active' => false]);
//        }

        if ($request->attribute('token_type_hint') === 'refresh_token') {
            throw new InvalidRequestException('Refresh token introspect is not available. You can only introspect access tokens');
        }

        $data = $this->unserializer->unserialize($request->attribute('token'));

        if (null === $data) {
            return new Response(['active' => false]);
        }

        //si pas resource owner et pas le propriétaire du tokent
//        if ($request->credentials()->id() !== $data['client_id']) {
//            return new Response(['active' => false]);
//        }

        if ($data['exp'] >= 0 && $data['exp'] < time()) {
            return new Response(['active' => false]);
        }

        $data['active'] = true;
        return new Response($data);
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
}