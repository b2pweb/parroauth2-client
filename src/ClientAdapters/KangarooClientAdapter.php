<?php

namespace Parroauth2\Client\ClientAdapters;

use Kangaroo\ApiScope;
use Kangaroo\Response as KangarooResponse;
use Parroauth2\Client\Exception\OAuthServerException;
use Parroauth2\Client\Exception\Parroauth2Exception;
use Parroauth2\Client\Request;
use Parroauth2\Client\Response;

/**
 * KangarooClientAdapter
 */
class KangarooClientAdapter implements ClientAdapterInterface
{
    /**
     * @var ApiScope
     */
    protected $api;

    /**
     * The oauth2 end points
     *
     * @var array
     */
    protected $endPoints = [
        'token' => 'token',
        'authorize' => 'authorize',
        'introspect' => 'introspect',
        'revoke' => 'revoke',
    ];

    /**
     * KangarooClientAdapter constructor.
     *
     * @param ApiScope $api
     * @param array $endPoints
     */
    public function __construct(ApiScope $api, array $endPoints = null)
    {
        $this->api = $api;

        if ($endPoints !== null) {
            $this->endPoints = $endPoints;
        }
    }

    /**
     * {@inheritdoc}
     *
     * @throws Parroauth2Exception
     */
    public function token(Request $request)
    {
        $response = $this->api->post($this->endPoints['token'], $request->attributes(), $request->queries(), $request->headers());

        if ($response->isError()) {
            // @see https://tools.ietf.org/html/rfc6749#section-5.2
            throw $this->internalError($response);
        }
        
        return new Response((array) $response->getBody());
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthorizationUri(Request $request, callable $onSuccess = null)
    {
        return $this->api->url($this->endPoints['authorize'], $request->queries());
    }

    /**
     * {@inheritdoc}
     *
     * @throws Parroauth2Exception
     */
    public function introspect(Request $request)
    {
        $response = $this->api->post($this->endPoints['introspect'], $request->attributes(), $request->queries(), $request->headers());

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
        $response = $this->api->post($this->endPoints['revoke'], $request->attributes(), $request->queries(), $request->headers());

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
                    return new Parroauth2Exception('An error has occurred:' . PHP_EOL . print_r($body->error, true), 400);
                } else {
                    return OAuthServerException::createFromResponse($body, $response->getStatusCode());
                }
            } else {
                return new Parroauth2Exception($body, 400);
            }
        }

        return new Parroauth2Exception('An error has occurred', 400);
    }
}