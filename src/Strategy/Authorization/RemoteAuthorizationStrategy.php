<?php

namespace Parroauth2\Client\Strategy\Authorization;

use DateTime;
use Kangaroo\Response;
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
     * @param string $token
     *
     * @return Grant
     *
     * @throws ConnectionException
     * @throws InternalErrorException
     */
    public function refresh($token)
    {
        $response = $this->client->api($this->config['path'])->post('token', [
            'grant_type'    => 'refresh_token',
            'client_id'     => $this->config['clientId'],
            'client_secret' => $this->config['clientSecret'],
            'refresh_token' => $token,
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
     * @param string $token
     *
     * @return $this
     *
     * @throws InternalErrorException
     */
    public function revoke($token)
    {
        $response = $this->client->api($this->config['path'])->post('revoke', [
            'client_id'     => $this->config['clientId'],
            'client_secret' => $this->config['clientSecret'],
            'token'         => $token,
        ]);

        if ($response->isError()) {
            // @see https://tools.ietf.org/html/rfc7009#section-2.2
            throw $this->internalError($response);
        }

        return $this;
    }

    /**
     * @param Response $response
     *
     * @return Grant
     */
    protected function createGrant(Response $response)
    {
        if ($response->isError()) {
            return null;
        }

        $body = $response->getBody();

        return new Grant(
            $body->access_token,
            (new DateTime())->setTimestamp(time() + (int)($body->expires_in * 0.9)),
            $body->refresh_token,
            $body->token_type
        );
    }
}