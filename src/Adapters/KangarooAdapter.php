<?php

namespace Parroauth2\Client\Adapters;

use Kangaroo\ApiScope;
use Kangaroo\Response as KangarooResponse;
use Parroauth2\Client\Exception\AccessDeniedException;
use Parroauth2\Client\Exception\InvalidClientException;
use Parroauth2\Client\Exception\InvalidGrantException;
use Parroauth2\Client\Exception\InvalidRequestException;
use Parroauth2\Client\Exception\InvalidScopeException;
use Parroauth2\Client\Exception\Parroauth2Exception;
use Parroauth2\Client\Exception\ServerErrorException;
use Parroauth2\Client\Exception\TemporarilyUnavailableException;
use Parroauth2\Client\Exception\UnauthorizedClientException;
use Parroauth2\Client\Exception\UnsupportedGrantTypeException;
use Parroauth2\Client\Exception\UnsupportedResponseTypeException;
use Parroauth2\Client\Request;
use Parroauth2\Client\Response;

/**
 * KangarooAdapter
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
        $response = $this->api->post('token', $request->attributes(), $request->queries(), $request->headers());

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
    public function authorize(Request $request, callable $onSuccess = null)
    {
        $location = $this->api->url('authorize', $request->queries());

        if ($onSuccess) {
            return call_user_func(
                $onSuccess,
                $location
            );
        }

        header('Location: ' . $location);
        exit;
    }

    /**
     * {@inheritdoc}
     *
     * @throws Parroauth2Exception
     */
    public function introspect(Request $request)
    {
        $response = $this->api->post('introspect', $request->attributes(), $request->queries(), $request->headers());

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
        $response = $this->api->post('revoke', $request->attributes(), $request->queries(), $request->headers());

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
                    switch ($body->error) {
                        case 'access_denied':
                            return new AccessDeniedException(isset($body->error_description) ? $body->error_description : 'Access denied', $response->getStatusCode());

                        case 'invalid_client':
                            return new InvalidClientException(isset($body->error_description) ? $body->error_description : 'Invalid client', $response->getStatusCode());

                        case 'invalid_grant':
                            return new InvalidGrantException(isset($body->error_description) ? $body->error_description : 'Invalid grant', $response->getStatusCode());

                        case 'invalid_request':
                            return new InvalidRequestException(isset($body->error_description) ? $body->error_description : 'Invalid request', $response->getStatusCode());

                        case 'invalid_scope':
                            return new InvalidScopeException(isset($body->error_description) ? $body->error_description : 'Invalid scope', $response->getStatusCode());

                        case 'server_error':
                            return new ServerErrorException(isset($body->error_description) ? $body->error_description : 'Server error', $response->getStatusCode());

                        case 'temporarily_unavailable':
                            return new TemporarilyUnavailableException(isset($body->error_description) ? $body->error_description : 'Temporarily unavailable', $response->getStatusCode());

                        case 'unauthorized_client':
                            return new UnauthorizedClientException(isset($body->error_description) ? $body->error_description : 'Unauthorized client', $response->getStatusCode());

                        case 'unsupported_grant_type':
                            return new UnsupportedGrantTypeException(isset($body->error_description) ? $body->error_description : 'Unsupported grant type', $response->getStatusCode());

                        case 'unsupported_response_type':
                            return new UnsupportedResponseTypeException(isset($body->error_description) ? $body->error_description : 'Unsupported response type', $response->getStatusCode());

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