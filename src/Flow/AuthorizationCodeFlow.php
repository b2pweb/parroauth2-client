<?php

namespace Parroauth2\Client\Flow;

use BadMethodCallException;
use InvalidArgumentException;
use Parroauth2\Client\Client;
use Parroauth2\Client\EndPoint\Authorization\AuthorizationCodeResponse;
use Parroauth2\Client\EndPoint\Token\TokenResponse;
use Parroauth2\Client\Exception\OAuthServerException;

/**
 * The authorization code grant flow
 *
 * - Generates the authorization URI with a state (cf: AuthorizationCodeFlow::authorizationUri())
 * - The client redirect the user agent to the generated URI
 * - The authorization provider validates the requests and redirect the user agent to the client
 * - Validates the provider's response (cf: AuthorizationCodeFlow::authorizationUri())
 * - Get an access token from the provider using the code response
 *
 * <code>
 * $flow = new AuthorizationCodeFlow($client);
 *
 * if (!$this->isLogged()) {
 *     if ($request->path() !== '/connect') {
 *         return $this->redirectTo($flow->authorizationUri($baseUrl.'/connect'));
 *     }
 *
 *     $this->setToken($flow->handleAuthorizationResponse($request->query());
 *     return $this->redirectTo($baseUrl);
 * }
 *
 * // Use token
 * </code>
 *
 * @see https://tools.ietf.org/html/rfc6749#section-4.1
 */
class AuthorizationCodeFlow implements AuthorizationFlowInterface
{
    /**
     * @var Client
     */
    private $client;


    /**
     * AuthorizationCodeFlow constructor.
     *
     * @param Client $client
     */
    public function __construct(Client $client)
    {
        $this->client = $client;
    }

    /**
     * {@inheritdoc}
     */
    public function authorizationUri(?string $redirectUri = null): string
    {
        $endpoint = $this->client->endPoints()->authorization()->code($redirectUri, $this->client->clientConfig()->scopes());

        $this->client->storage()->store('authorization', $endpoint->parameters());

        return $endpoint->uri();
    }

    /**
     * {@inheritdoc}
     *
     * @throws \Http\Client\Exception When an HTTP error occurs
     */
    public function handleAuthorizationResponse(array $queryParameters): TokenResponse
    {
        if (!$this->client->storage()->has('authorization')) {
            throw new BadMethodCallException('The authorization flow is not started');
        }

        $request = $this->client->storage()->remove('authorization');
        $response = new AuthorizationCodeResponse($queryParameters);

        if (!hash_equals($request['state'], $response->state())) {
            throw new InvalidArgumentException('Invalid state');
        }

        if ($response->isError()) {
            throw OAuthServerException::create($response->error(), $response->errorDescription());
        }

        $token = $this->client->endPoints()->token()
            ->code($response->code(), $request['redirect_uri'] ?? null)
            ->call()
        ;

        return $token;
    }
}
