<?php

namespace Parroauth2\Client\ClientAdapters;

use Parroauth2\Client\Exception\ParsingException;
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
    public function authorize(Request $request, callable $onSuccess = null)
    {
        if ($this->delegate !== null) {
            return $this->delegate->authorize($request, $onSuccess);
        }

        throw new InvalidRequestException('Authorize procedure is not available');
    }

    /**
     * {@inheritdoc}
     */
    public function introspect(Request $request)
    {
        if ($request->query('token_type_hint') == 'refresh_token') {
            throw new InvalidRequestException('Refresh token introspect is not available. You can only introspect access tokens', 400);
        }

        try {
            $data = $this->unserializer->unserialize($request->query('token'));

            if ($data['exp'] >= 0) {
                $data['active'] = 0 < ($data['exp'] - time());
            } else {
                $data['active'] = true;
            }

            if ($data['active'] && $data['client_id'] !== '' && $request->credentials()) {
                $data['active'] = $request->credentials()->id() == $data['client_id'];
            }

            if ($data['active']) {
                return new Response($data);
            }
        } catch (ParsingException $e) {
        }

        return new Response(['active' => false]);
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