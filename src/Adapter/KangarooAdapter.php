<?php

namespace Parroauth2\Client\Adapter;

use DateTime;
use Kangaroo\Client;
use Kangaroo\Response;
use Parroauth2\Client\Exception\ConnectionException;
use Parroauth2\Client\Exception\InternalErrorException;
use Parroauth2\Client\Grant;

/**
 * Class KangarooAdapter
 *
 * @package Parroauth2\Client\Adapter
 */
class KangarooAdapter implements AdapterInterface
{
    /**
     * @var Client
     */
    protected $client;

    /**
     * @var array
     */
    protected $config;

    /**
     * Client constructor.
     *
     * @param Client $client
     * @param array $config
     */
    public function __construct(Client $client, $config)
    {
        $this->client = $client;

        $this->config = array_merge(
            [
                'path'         => '/',
                'clientId'     => '',
                'clientSecret' => '',
            ],
            $config
        );
    }

    /**
     * @inheritdoc
     *
     * @throws ConnectionException
     * @throws InternalErrorException
     */
    public function token($username, $password)
    {
        $response = $this->client->api($this->config['path'])->post('token', [
            'grant_type'    => 'password',
            'client_id'     => $this->config['clientId'],
            'client_secret' => $this->config['clientSecret'],
            'username'      => $username,
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
     * @inheritdoc
     *
     * @throws ConnectionException
     * @throws InternalErrorException
     */
    public function refresh($token)
    {
        if ($token instanceof Grant) {
            $token = $token->getRefresh();
        }

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
     * @inheritdoc
     *
     * @throws InternalErrorException
     */
    public function userinfo($token)
    {
        $response = $this->client->api($this->config['path'])->post('userinfo', []);

        if ($response->isError()) {
            throw $this->internalError($response);
        }

        return (array)$response->getBody();
    }

    /**
     * @inheritdoc
     *
     * @throws InternalErrorException
     */
    public function introspect($token)
    {
        if ($token instanceof Grant) {
            $token = $token->getAccess();
        }

        $response = $this->client->api($this->config['path'])->post('introspect', [
            'client_id'     => $this->config['clientId'],
            'client_secret' => $this->config['clientSecret'],
            'token'         => $token,
        ]);

        if ($response->isError()) {
            // @see https://tools.ietf.org/html/rfc7662#section-2.3
            throw $this->internalError($response);
        }

        return (array)$response->getBody();
    }

    /**
     * @inheritdoc
     *
     * @throws InternalErrorException
     */
    public function revoke($token)
    {
        if ($token instanceof Grant) {
            $token = $token->getAccess();
        }

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
            $body->refresh_token
        );
    }

    /**
     * @param Response $response
     *
     * @return InternalErrorException
     */
    protected function internalError($response)
    {
        $messageData = [
            'Configuration error',
            'Status code: ' . $response->getStatusCode(),
        ];

        if ($body = $response->getBody()) {
            if (is_object($body)) {
                if (is_object($body->error)) {
                    $messageData[] = 'Error: ' . print_r($body->error, true);
                } else {
                    $messageData[] = 'Error: ' . $body->error;

                    if (isset($body->error_description)) {
                        $messageData[] = 'Error description: ' . $body->error_description;
                    }

                    if (isset($body->error_uri)) {
                        $messageData[] = 'Error URI: ' . $body->error_uri;
                    }
                }
            } else {
                $messageData[] = 'Error: ' . $body;
            }
        }

        return new InternalErrorException(implode(PHP_EOL, $messageData), 500);
    }
}