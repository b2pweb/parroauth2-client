<?php

namespace Parroauth2\Client\Strategy\Introspection;

use Parroauth2\Client\Exception\InternalErrorException;
use Parroauth2\Client\Grant;
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
    public function introspect($grant)
    {
        if ($grant instanceof Grant) {
            $grant = $grant->getAccess();
        }

        $response = $this->client->api($this->config['path'])->post('introspect', [
            'client_id'     => $this->config['clientId'],
            'client_secret' => $this->config['clientSecret'],
            'token'         => $grant,
        ]);

        if ($response->isError()) {
            // @see https://tools.ietf.org/html/rfc7662#section-2.3
            throw $this->internalError($response);
        }

        return (array)$response->getBody();
    }
}