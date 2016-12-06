<?php

namespace Parroauth2\Client;

use InvalidArgumentException;
use Parroauth2\Client\Adapters\AdapterInterface;
use Parroauth2\Client\GrantTypes\AuthorizationGrantType;
use Parroauth2\Client\GrantTypes\GrantTypeInterface;
use Parroauth2\Client\GrantTypes\PasswordGrantType;
use Parroauth2\Client\GrantTypes\RefreshGrantType;

/**
 * Class Client
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
     *
     * @todo Manage credentials like acquaint grant type (if possible, due to 'prepare' method param)
     */
    public function __construct(AdapterInterface $adapter, ClientCredentials $credentials = null)
    {
        $this->adapter = $adapter;
        $this->credentials = $credentials;
    }

    /**
     * @param string $username
     * @param string $password
     * @param string[] $scopes
     * 
     * @return Authorization
     */
    public function login($username, $password, array $scopes = [])
    {
        return $this->token(new PasswordGrantType($username, $password, $scopes));
    }

    /**
     * @param Authorization|string $token
     * @param string[] $scopes
     *
     * @return Authorization
     */
    public function refresh($token, array $scopes = [])
    {
        if ($token instanceof Authorization) {
            $token = $token->getRefresh();
        }

        return $this->token(new RefreshGrantType($token, $scopes));
    }

    /**
     * @param string $code
     * @param string $redirectUri
     * @param string $clientId
     * @param string[] $scopes
     *
     * @return Authorization
     */
    public function tokenFromAuthorizationCode($code, $redirectUri, $clientId, array $scopes = [])
    {
        return $this->token(new AuthorizationGrantType($code, $redirectUri, $clientId, $scopes));
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
     * @param string $redirectUri
     * @param string[] $scopes
     * @param string $state
     * @param string $clientId
     * @param callable $onSuccess
     */
    public function authorize($redirectUri, array $scopes = [], $state = '', $clientId = '', callable $onSuccess = null)
    {
        $request = (new Request())
            ->setParameters([
                'response_type' => 'code',
                'redirect_uri' => $redirectUri,
            ])
        ;

        if ($scopes) {
            $request->setParameter('scope', implode(' ', $scopes));
        }

        if ($state) {
            $request->setParameter('state', $state);
        }

        if (!$clientId && $this->credentials) {
            $clientId = $this->credentials->getId();
        }

        if (!$clientId) {
            throw new InvalidArgumentException('Client id is required');
        }

        $request->setParameter('client_id', $clientId);

        $this->adapter->authorize($request, $onSuccess);
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