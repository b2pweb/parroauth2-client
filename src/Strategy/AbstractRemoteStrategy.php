<?php

namespace Parroauth2\Client\Strategy;

use Kangaroo\Client;
use Kangaroo\Response;
use Parroauth2\Client\Exception\InternalErrorException;

/**
 * Class AbstractRemoteStrategy
 *
 * @package Parroauth2\Client\Strategy
 */
abstract class AbstractRemoteStrategy
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
     * RemoteAuthorizationStrategy constructor.
     *
     * @param Client $client
     * @param array $config
     */
    public function __construct(Client $client, array $config)
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