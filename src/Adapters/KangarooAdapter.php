<?php

namespace Parroauth2\Client\Adapters;

use Kangaroo\ApiScope;
use Kangaroo\Response as KangarooResponse;
use Parroauth2\Client\Response;
use Parroauth2\Client\Exception\ConnectionException;
use Parroauth2\Client\Exception\InternalErrorException;
use Parroauth2\Client\Request;

/**
 * Class KangarooAdapter
 * 
 * @package Parroauth2\Client\Adapters
 */
class KangarooAdapter implements AdapterInterface
{
    /**
     * @var ApiScope
     */
    protected $api;

    /**
     * KangarooAdapter constructor.
     *
     * @param ApiScope $api
     */
    public function __construct(ApiScope $api)
    {
        $this->api = $api;
    }

    /**
     * {@inheritdoc}
     *
     * @throws InternalErrorException
     */
    public function token(Request $request)
    {
        $headers = [];

        if ($request->getCredentials()) {
            $headers['client_id'] = $request->getCredentials()->getId();
            $headers['client_secret'] = $request->getCredentials()->getSecret();
        }

        $response = $this->api->post('token', $request->getParameters(), [], $headers);

        if ($response->isError()) {
            // @see https://tools.ietf.org/html/rfc6749#section-5.2
            if ($response->getStatusCode() == 400 && $response->getBody()->error == 'invalid_grant') {
                throw new ConnectionException('Invalid credentials');
            }

            throw $this->internalError($response);
        }
        
        return new Response((array) $response->getBody());
    }

    /**
     * {@inheritdoc}
     *
     * @throws InternalErrorException
     */
    public function introspect(Request $request)
    {
        $headers = [];

        if ($request->getCredentials()) {
            $headers['client_id'] = $request->getCredentials()->getId();
            $headers['client_secret'] = $request->getCredentials()->getSecret();
        }

        $response = $this->api->post('introspect', $request->getParameters(), [], $headers);

        if ($response->isError()) {
            // @see https://tools.ietf.org/html/rfc7662#section-2.3
            throw $this->internalError($response);
        }

        return new Response((array) $response->getBody());
    }

    /**
     * {@inheritdoc}
     *
     * @throws InternalErrorException
     */
    public function revoke(Request $request)
    {
        $headers = [];

        if ($request->getCredentials()) {
            $headers['client_id'] = $request->getCredentials()->getId();
            $headers['client_secret'] = $request->getCredentials()->getSecret();
        }

        $response = $this->api->post('revoke', $request->getParameters(), [], $headers);

        if ($response->isError()) {
            // @see https://tools.ietf.org/html/rfc7009#section-2.2
            throw $this->internalError($response);
        }
        
        return new Response();
    }

    /**
     * @param KangarooResponse $response
     *
     * @return InternalErrorException
     */
    protected function internalError(KangarooResponse $response)
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