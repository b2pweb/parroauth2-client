<?php

namespace Parroauth2\Client\Strategy\Introspection;

use Parroauth2\Client\Exception\InternalErrorException;
use Parroauth2\Client\Introspection;
use Parroauth2\Client\Strategy\AbstractRemoteStrategy;

/**
 * Class RemoteIntrospectionStrategy
 *
 * @package Parroauth2\Client\Strategy\Introspection
 */
class RemoteIntrospectionStrategy extends AbstractRemoteStrategy implements IntrospectionStrategyInterface
{
    /**
     * {@inheritdoc}
     *
     * @throws InternalErrorException
     */
    public function introspect($token)
    {
        $response = $this->client->api($this->config['path'])->post('introspect', [
            'client_id'     => $this->config['clientId'],
            'client_secret' => $this->config['clientSecret'],
            'token'         => $token,
        ]);

        if ($response->isError()) {
            // @see https://tools.ietf.org/html/rfc7662#section-2.3
            throw $this->internalError($response);
        }

        $body = $response->getBody();

        $introspection = new Introspection();
        $introspection->setActive($body->active);

        if (isset($body->scope)) {
            $introspection->setScopes(explode(' ', $body->scope));
        }

        if (isset($body->metadata)) {
            $introspection->setMetadata($body->metadata);
        }

        return $introspection;
    }
}