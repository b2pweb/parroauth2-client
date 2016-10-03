<?php

namespace Parroauth2\Client;

use DateTime;
use Parroauth2\Client\Adapters\AdapterInterface;
use Parroauth2\Client\GrantTypes\AuthorizationGrantType;
use Parroauth2\Client\GrantTypes\GrantTypeInterface;
use Parroauth2\Client\GrantTypes\PasswordGrantType;
use Parroauth2\Client\GrantTypes\RefreshGrantType;

/**
 * Class Client
 * 
 * @package Parroauth2\Client
 */
class Client
{
    /**
     * @var AdapterInterface
     */
    protected $adapter;

    /**
     * @var ClientCredentials
     */
    protected $credentials;

    /**
     * Client constructor.
     *
     * @param AdapterInterface $adapter
     * @param ClientCredentials $credentials
     */
    public function __construct(AdapterInterface $adapter, ClientCredentials $credentials = null)
    {
        $this->adapter = $adapter;
        $this->credentials = $credentials;
    }

    /**
     * @param string $username
     * @param string $password
     * @param string $scope
     * 
     * @return Authorization
     */
    public function login($username, $password, $scope = '')
    {
        return $this->token(new PasswordGrantType($username, $password, $scope));
    }

    /**
     * @param Authorization|string $token
     * @param string $scope
     * 
     * @return Authorization
     */
    public function refresh($token, $scope = '')
    {
        if ($token instanceof Authorization) {
            $token = $token->getRefresh();
        }

        return $this->token(new RefreshGrantType($token, $scope));
    }

    /**
     * @param string $code
     * @param string $redirectUri
     * @param string $clientId
     * 
     * @return Authorization
     */
    public function authorize($code, $redirectUri = '', $clientId = '')
    {
        return $this->token(new AuthorizationGrantType($code, $redirectUri, $clientId));
    }

    /**
     * @param GrantTypeInterface $grantType
     *
     * @return Authorization
     */
    public function token(GrantTypeInterface $grantType)
    {
        $request = new Request([], $this->credentials);

        $grantType->acquaint($request);

        $response = $this->adapter->token($request);

        return new Authorization(
            $response->getBodyItem('access_token'),
            $response->getBodyItem('token_type'),
            $response->getBodyItem('expires_in'),
            $response->getBodyItem('refresh_token'),
            explode(' ', $response->getBodyItem('scope', ''))
        );
    }

    /**
     * @param Authorization|string $token
     * @param string $hint
     * 
     * @return mixed
     */
    public function introspect($token, $hint = '')
    {
        if ($token instanceof Authorization) {
            if (!$hint && $hint == 'access_token') {
                $token = $token->getAccess();
            } else {
                $token = $token->getRefresh();
            }
        }

        $request = new Request(['token' => $token], $this->credentials);
        
        if ($hint) {
            $request->setParameter('token_type_hint', $hint);
        }

        return Introspection::fromResponse($this->adapter->introspect($request));
    }

    /**
     * @param Authorization|string $token
     * @param string $hint
     */
    public function revoke($token, $hint = '')
    {
        if ($token instanceof Authorization) {
            if (!$hint && $hint == 'access_token') {
                $token = $token->getAccess();
            } else {
                $token = $token->getRefresh();
            }
        }

        $request = new Request(['token' => $token], $this->credentials);

        if ($hint) {
            $request->setParameter('token_type_hint', $hint);
        }

        $this->adapter->revoke($request);
    }
}