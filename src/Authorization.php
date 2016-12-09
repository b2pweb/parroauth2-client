<?php

namespace Parroauth2\Client;

/**
 * Authorization
 */
class Authorization
{
    /**
     * The access token
     *
     * @var string
     */
    protected $accessToken;

    /**
     * The type of token
     *
     * @var string
     */
    protected $tokenType;

    /**
     * The token lifetime
     *
     * @var int
     */
    protected $lifetime;

    /**
     * The refresh token
     *
     * @var string
     */
    protected $refreshToken;

    /**
     * The scopes
     *
     * @var string[]
     */
    protected $scopes;

    /**
     * Authorization constructor.
     *
     * @param string $accessToken
     * @param string $tokenType
     * @param int $lifetime
     * @param string $refreshToken
     * @param string[] $scopes
     */
    public function __construct($accessToken, $tokenType, $lifetime = null, $refreshToken = '', array $scopes = [])
    {
        $this->accessToken = $accessToken;
        $this->tokenType = $tokenType;
        $this->lifetime = $lifetime;
        $this->refreshToken = $refreshToken;
        $this->scopes = $scopes;
    }

    /**
     * Set the access token
     *
     * @param string $accessToken
     */
    public function setAccessToken($accessToken)
    {
        $this->accessToken = $accessToken;
    }

    /**
     * Get the access token
     *
     * @return string
     */
    public function accessToken()
    {
        return $this->accessToken;
    }

    /**
     * Set the token type
     *
     * @param string $type
     */
    public function setTokenType($type)
    {
        $this->tokenType = $type;
    }

    /**
     * Get the token type
     *
     * @return string
     */
    public function tokenType()
    {
        return $this->tokenType;
    }

    /**
     * Set the token life time
     *
     * @param int $lifetime
     */
    public function setLifetime($lifetime)
    {
        $this->lifetime = $lifetime;
    }

    /**
     * Get the token life time
     *
     * @return int
     */
    public function lifetime()
    {
        return $this->lifetime;
    }

    /**
     * Check whether the token is expired
     *
     * @return bool
     */
    public function isExpired()
    {
        if (null === $this->lifetime) {
            return false;
        }

        return 0 > $this->lifetime;
    }

    /**
     * Set the refresh token
     *
     * @param string $refreshToken
     */
    public function setRefresh($refreshToken)
    {
        $this->refreshToken = $refreshToken;
    }

    /**
     * Get the refresh token
     *
     * @return string
     */
    public function refreshToken()
    {
        return $this->refreshToken;
    }

    /**
     * Set the scopes
     *
     * @param string[] $scopes
     *
     * @return Authorization
     */
    public function setScopes(array $scopes)
    {
        $this->scopes = $scopes;

        return $this;
    }

    /**
     * Get the scopes
     *
     * @return string[]
     */
    public function scopes()
    {
        return $this->scopes;
    }

    /**
     * Check whether the token has this scope
     *
     * @param string $scope
     *
     * @return bool
     */
    public function hasScope($scope)
    {
        return in_array($scope, $this->scopes);
    }
}