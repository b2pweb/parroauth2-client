<?php

namespace Parroauth2\Client\Adapters;

use Parroauth2\Client\Exception\InternalErrorException;
use Parroauth2\Client\Exception\ParsingException;
use Parroauth2\Client\Request;
use Parroauth2\Client\Response;
use Parroauth2\Client\Unserializer\UnserializerInterface;

/**
 * Class SelfAdapter
 *
 * @package Parroauth2\Client\Adapters
 */
class SelfAdapter implements AdapterInterface
{
    /**
     * @var UnserializerInterface
     */
    protected $unserializer;

    /**
     * SelfIntrospectionStrategy constructor.
     *
     * @param UnserializerInterface $unserializer
     */
    public function __construct(UnserializerInterface $unserializer)
    {
        $this->unserializer = $unserializer;
    }

    /**
     * {@inheritdoc}
     *
     * @throws InternalErrorException
     */
    public function token(Request $request)
    {
        throw new InternalErrorException('Access granting is not available');
    }

    /**
     * {@inheritdoc}
     */
    public function introspect(Request $request)
    {
        if ($request->getParameter('token_type_hint') == 'refresh_token') {
            throw new InternalErrorException('Refresh token introspect is not available. You can only introspect access tokens');
        }

        try {
            $data = $this->unserializer->unserialize($request->getParameter('token'));

            if (isset($data['exp'])) {
                $data['active'] = 0 < ($data['exp'] - time());
            }

            if ($data['active'] && !empty($data['client_id']) && $request->getCredentials()) {
                $data['active'] = $request->getCredentials()->getId() == $data['client_id'];
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
     * @throws InternalErrorException
     */
    public function revoke(Request $request)
    {
        throw new InternalErrorException('Access revoking is not available');
    }
}