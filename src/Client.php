<?php

namespace Parroauth2\Client;

use InvalidArgumentException;
use Parroauth2\Client\ClientAdapters\ClientAdapterInterface;
use Parroauth2\Client\Credentials\ClientCredentials;
use Parroauth2\Client\GrantTypes\AuthorizationCodeGrantType;
use Parroauth2\Client\GrantTypes\GrantTypeInterface;
use Parroauth2\Client\GrantTypes\PasswordGrantType;
use Parroauth2\Client\GrantTypes\RefreshTokenGrantType;

/**
 * The oauth2 client
 */
class Client
{
    /**
     * The http client
     *
     * @var ClientAdapterInterface
     */
    protected $client;

    /**
     * The client credentials
     *
     * @var null|ClientCredentials
     */
    protected $credentials;

    /**
     * Client constructor.
     *
     * @param ClientAdapterInterface $adapter
     * @param null|ClientCredentials $credentials
     */
    public function __construct(ClientAdapterInterface $client, ClientCredentials $credentials = null)
    {
        $this->client = $client;
        $this->credentials = $credentials;
    }

    /**
     * Request for token from username / password
     *
     * @param string $username
     * @param string $password
     * @param null|string[] $scopes
     * 
     * @return Authorization
     */
    public function login($username, $password, array $scopes = null)
    {
        return $this->token(new PasswordGrantType($username, $password, $scopes));
    }

    /**
     * Refresh the token
     *
     * @param Authorization|string $token
     * @param null|string[] $scopes
     *
     * @return Authorization
     */
    public function refresh($token, array $scopes = null)
    {
        if ($token instanceof Authorization) {
            $token = $token->refreshToken();
        }

        return $this->token(new RefreshTokenGrantType($token, $scopes));
    }

    /**
     * Request the token from authorization code
     *
     * @param string $code
     * @param null|string $redirectUri
     * @param null|string $clientId
     *
     * @return Authorization
     */
    public function tokenFromAuthorizationCode($code, $redirectUri = null, $clientId = null)
    {
        return $this->token(new AuthorizationCodeGrantType($code, $redirectUri, $clientId));
    }

    /**
     * Request a token from the oauth2 grant type
     *
     * @param GrantTypeInterface $grantType
     *
     * @return Authorization
     */
    public function token(GrantTypeInterface $grantType)
    {
        $request = new Request([], [], $this->credentials);

        $grantType->acquaint($request);

        $response = $this->client->token($request);

        return new Authorization(
            $response->getBodyItem('access_token'),
            $response->getBodyItem('token_type'),
            $response->getBodyItem('expires_in', -1),
            $response->getBodyItem('refresh_token'),
            explode(' ', $response->getBodyItem('scope', '')),
            $response->getBodyItem('id_token')
        );
    }

    /**
     * Get the authorization uri
     *
     * @param string $redirectUri
     * @param null|string[] $scopes
     * @param null|string $state
     * @param null|string $clientId
     * @param array $parameters
     *
     * @return string
     */
    public function getAuthorizationUri($redirectUri, array $scopes = null, $state = null, $clientId = null, array $parameters = [])
    {
        if ($scopes !== null) {
            $scopes = implode(' ', $scopes);
        }

        if ($clientId === null && $this->credentials !== null) {
            $clientId = $this->credentials->id();
        }

        if ($clientId === null) {
            throw new InvalidArgumentException('Client id is required');
        }

        $parameters['response_type'] = 'code';
        $parameters['redirect_uri'] = $redirectUri;
        $parameters['scope'] = $scopes;
        $parameters['state'] = $state;
        $parameters['client_id'] = $clientId;

        $request = new Request(array_filter($parameters));

        return $this->client->getAuthorizationUri($request);
    }

    /**
     * Introspect a token
     *
     * @param Authorization|string $token
     * @param string $hint
     * 
     * @return mixed
     */
    public function introspect($token, $hint = null)
    {
        if ($token instanceof Authorization) {
            if ($hint === null || $hint === 'access_token') {
                $token = $token->accessToken();
            } else {
                $token = $token->refreshToken();
            }
        }

        $request = new Request([], ['token' => $token], $this->credentials);
        
        if ($hint !== null) {
            $request->addAttribute('token_type_hint', $hint);
        }

        return Introspection::fromResponse($this->client->introspect($request));
    }

    /**
     * Revoke the token
     *
     * @param Authorization|string $token
     * @param string $hint
     */
    public function revoke($token, $hint = null)
    {
        if ($token instanceof Authorization) {
            if ($hint === null || $hint === 'access_token') {
                $token = $token->accessToken();
            } else {
                $token = $token->refreshToken();
            }
        }

        $request = new Request([], ['token' => $token], $this->credentials);

        if ($hint) {
            $request->addAttribute('token_type_hint', $hint);
        }

        $this->client->revoke($request);
    }
}