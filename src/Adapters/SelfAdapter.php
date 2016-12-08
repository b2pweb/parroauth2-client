<?php

namespace Parroauth2\Client\Adapters;

use Parroauth2\Client\Exception\ParsingException;
use Parroauth2\Client\Request;
use Parroauth2\Client\Response;
use Parroauth2\Client\Unserializer\UnserializerInterface;
use Parroauth2\Client\Exception\InvalidRequestException;

/**
 * Class SelfAdapter
 */
class SelfAdapter implements AdapterInterface
{
    /**
     * @var UnserializerInterface
     */
    protected $unserializer;

    /**
     * the delegate adapter
     *
     * @var AdapterInterface
     */
    protected $delegate;

    /**
     * SelfIntrospectionStrategy constructor.
     *
     * @param UnserializerInterface $unserializer
     * @param AdapterInterface $delegate
     */
    public function __construct(UnserializerInterface $unserializer, AdapterInterface $delegate = null)
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

            if (isset($data['exp'])) {
                $data['active'] = 0 < ($data['exp'] - time());
            }

            if ($data['active'] && !empty($data['client_id']) && $request->credentials()) {
                $data['active'] = $request->credentials()->id() == $data['client_id'];
            }

            if (!isset($data['active'])) {
                $data['active'] = true;
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