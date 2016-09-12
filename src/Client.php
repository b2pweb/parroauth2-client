<?php

namespace Parroauth2\Client;

use Bdf\Config\Config;
use DateTime;
use Kangaroo\Client as BaseClient;
use Kangaroo\Response;
use Parroauth2\Client\Exception\ConnectionException;
use Parroauth2\Client\Exception\InternalErrorException;

/**
 * Class Client
 *
 * @package Parroauth2\Client\Client
 */
class Client
{
    /**
     * @var BaseClient
     */
    protected $client;

    /**
     * @var Config
     */
    protected $config;

    /**
     * Client constructor.
     *
     * @param BaseClient $client
     * @param Config $config
     */
    public function __construct(BaseClient $client, Config $config)
    {
        $this->client = $client;
        $this->config = $config;
    }

    /**
     * @param string $username
     * @param string $password
     *
     * @return Token
     *
     * @throws ConnectionException
     * @throws InternalErrorException
     */
    public function token($username, $password)
    {
        $response = $this->client->api($this->config->get('path', '/'))->post('token', [
            'grant_type'    => 'password',
            'client_id'     => $this->config->get('clientId'),
            'client_secret' => $this->config->get('clientSecret'),
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

        return $this->createToken($response);
    }

    /**
     * @param Token|string $token
     *
     * @return Token
     *
     * @throws ConnectionException
     * @throws InternalErrorException
     */
    public function refresh($token)
    {
        if ($token instanceof Token) {
            $token = $token->getRefresh();
        }

        $response = $this->client->api($this->config->get('path', '/'))->post('token', [
            'grant_type'    => 'refresh_token',
            'client_id'     => $this->config->get('clientId'),
            'client_secret' => $this->config->get('clientSecret'),
            'refresh_token' => $token,
        ]);

        if ($response->isError()) {
            // @see https://tools.ietf.org/html/rfc6749#section-5.2
            if ($response->getStatusCode() == 400 && $response->getBody()->error == 'invalid_grant') {
                throw new ConnectionException('Invalid token');
            }

            throw $this->internalError($response);
        }

        return $this->createToken($response);
    }

    /**
     * @param Token|string $token
     *
     * @return array
     *
     * @throws InternalErrorException
     */
    public function userinfo($token)
    {
        $response = $this->client->api($this->config->get('path', '/'))->post('userinfo', []);

        if ($response->isError()) {
            throw $this->internalError($response);
        }

        return (array)$response->getBody();
    }

    /**
     * @param Token|string $token
     *
     * @return array
     *
     * @throws InternalErrorException
     */
    public function introspect($token)
    {
        if ($token instanceof Token) {
            $token = $token->getAccess();
        }

        $response = $this->client->api($this->config->get('path', '/'))->post('introspect', [
            'client_id'     => $this->config->get('clientId'),
            'client_secret' => $this->config->get('clientSecret'),
            'token'         => $token,
        ]);

        if ($response->isError()) {
            // @see https://tools.ietf.org/html/rfc7662#section-2.3
            throw $this->internalError($response);
        }

        return (array)$response->getBody();
    }

    /**
     * @param Token|string $token
     *
     * @return $this
     *
     * @throws InternalErrorException
     */
    public function revoke($token)
    {
        if ($token instanceof Token) {
            $token = $token->getAccess();
        }

        $response = $this->client->api($this->config->get('path', '/'))->post('revoke', [
            'client_id'     => $this->config->get('clientId'),
            'client_secret' => $this->config->get('clientSecret'),
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
     * @return Token
     */
    protected function createToken(Response $response)
    {
        if ($response->isError()) {
            return null;
        }

        $body = $response->getBody();

        return new Token(
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