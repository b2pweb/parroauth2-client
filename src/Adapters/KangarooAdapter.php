<?php

namespace Parroauth2\Client\Adapters;

use Kangaroo\ApiScope;
use Kangaroo\Response as KangarooResponse;
use Parroauth2\Client\Exception\InvalidClientException;
use Parroauth2\Client\Exception\InvalidGrantException;
use Parroauth2\Client\Exception\InvalidRequestException;
use Parroauth2\Client\Exception\InvalidScopeException;
use Parroauth2\Client\Exception\Parroauth2Exception;
use Parroauth2\Client\Exception\UnauthorizedClientException;
use Parroauth2\Client\Exception\UnsupportedGrantTypeException;
use Parroauth2\Client\Request;
use Parroauth2\Client\Response;

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
     * @throws Parroauth2Exception
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
            throw $this->internalError($response);
        }
        
        return new Response((array) $response->getBody());
    }

    /**
     * {@inheritdoc}
     *
     * @throws Parroauth2Exception
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
     * @throws Parroauth2Exception
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
     * @return Parroauth2Exception
     */
    protected function internalError(KangarooResponse $response)
    {
        if ($body = $response->getBody()) {
            if (is_object($body)) {
                if (is_object($body->error)) {
                    return new Parroauth2Exception('An error has occurred:' . PHP_EOL . print_r($body->error), 400);
                } else {
                    switch ($body->error) {
                        case 'invalid_request':
                            return new InvalidRequestException(isset($body->error_description) ? $body->error_description : 'Invalid request', $response->getStatusCode());

                        case 'invalid_client':
                            return new InvalidClientException(isset($body->error_description) ? $body->error_description : 'Invalid client', $response->getStatusCode());

                        case 'invalid_grant':
                            return new InvalidGrantException(isset($body->error_description) ? $body->error_description : 'Invalid grant', $response->getStatusCode());

                        case 'unauthorized_client':
                            return new UnauthorizedClientException(isset($body->error_description) ? $body->error_description : 'Unauthorized client', $response->getStatusCode());

                        case 'unsupported_grant_type':
                            return new UnsupportedGrantTypeException(isset($body->error_description) ? $body->error_description : 'Unsupported grant type', $response->getStatusCode());

                        case 'invalid_scope':
                            return new InvalidScopeException(isset($body->error_description) ? $body->error_description : 'Invalid scope', $response->getStatusCode());

                        default:
                            return new Parroauth2Exception(isset($body->error_description) ? $body->error_description : 'An error has occurred', 400);
                    }
                }
            } else {
                return new Parroauth2Exception($body->error, 400);
            }
        }

        return new Parroauth2Exception('An error has occurred', 400);
    }
}