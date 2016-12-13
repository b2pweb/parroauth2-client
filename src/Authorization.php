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
     * @param null|string $refreshToken
     * @param string[] $scopes
     */
    public function __construct($accessToken, $tokenType, $lifetime = -1, $refreshToken = null, array $scopes = [])
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
     * Set the refresh token
     *
     * @param string $refreshToken
     */
    public function setRefreshToken($refreshToken)
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

    /**
     * Check whether the authorization is expired
     *
     * @param int $delta A life time tolerance
     *
     * @return boolean
     */
    public function isExpired($delta = 0)
    {
        return $this->lifetime >= 0 && $this->lifetime <= (time() + $delta);
    }

    /**
     * Check whether the authorization can be refreshed
     *
     * @param int $delta A life time tolerance
     *
     * @return boolean
     */
    public function canBeRefreshed()
    {
        return $this->refreshToken !== null;
    }

    /**
     * Check whether the authorization should be refreshed
     *
     * @param int $delta A life time tolerance
     *
     * @return boolean
     */
    public function shouldBeRefreshed($delta = 1)
    {
        return $this->canBeRefreshed() && $this->isExpired($delta);
    }
}