<?php

namespace Parroauth2\Client\Strategy\Authorization;

use Parroauth2\Client\Exception\ConnectionException;
use Parroauth2\Client\Exception\InternalErrorException;
use Parroauth2\Client\Grant;
use Parroauth2\Client\Strategy\AbstractRemoteStrategy;

/**
 * Class RemoteAuthorizationStrategy
 *
 * @package Parroauth2\Client\Strategy\Authorization
 */
class RemoteAuthorizationStrategy extends AbstractRemoteStrategy implements AuthorizationStrategyInterface
{
    /**
     * @param string $login
     * @param string $password
     *
     * @return Grant
     *
     * @throws ConnectionException
     * @throws InternalErrorException
     */
    public function token($login, $password)
    {
        $response = $this->client->api($this->config['path'])->post('token', [
            'grant_type'    => 'password',
            'client_id'     => $this->config['clientId'],
            'client_secret' => $this->config['clientSecret'],
            'username'      => $login,
            'password'      => $password,
        ]);

        if ($response->isError()) {
            // @see https://tools.ietf.org/html/rfc6749#section-5.2
            if ($response->getStatusCode() == 400 && $response->getBody()->error == 'invalid_grant') {
                throw new ConnectionException('Invalid credentials');
            }

            throw $this->internalError($response);
        }

        return $this->createGrant($response);
    }

    /**
     * @param Grant|string $grant
     *
     * @return Grant
     *
     * @throws ConnectionException
     * @throws InternalErrorException
     */
    public function refresh($grant)
    {
        if ($grant instanceof Grant) {
            $grant = $grant->getRefresh();
        }

        $response = $this->client->api($this->config['path'])->post('token', [
            'grant_type'    => 'refresh_token',
            'client_id'     => $this->config['clientId'],
            'client_secret' => $this->config['clientSecret'],
            'refresh_token' => $grant,
        ]);

        if ($response->isError()) {
            // @see https://tools.ietf.org/html/rfc6749#section-5.2
            if ($response->getStatusCode() == 400 && $response->getBody()->error == 'invalid_grant') {
                throw new ConnectionException('Invalid token');
            }

            throw $this->internalError($response);
        }

        return $this->createGrant($response);
    }

    /**
     * @param Grant|string $grant
     *
     * @return $this
     *
     * @throws InternalErrorException
     */
    public function revoke($grant)
    {
        if ($grant instanceof Grant) {
            $grant = $grant->getAccess();
        }

        $response = $this->client->api($this->config['path'])->post('revoke', [
            'client_id'     => $this->config['clientId'],
            'client_secret' => $this->config['clientSecret'],
            'token'         => $grant,
        ]);

        if ($response->isError()) {
            // @see https://tools.ietf.org/html/rfc7009#section-2.2
            throw $this->internalError($response);
        }

        return $this;
    }
}