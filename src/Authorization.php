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
    private $accessToken;

    /**
     * The type of token
     *
     * @var string
     */
    private $tokenType;

    /**
     * The token lifetime
     *
     * @var int
     */
    private $lifetime;

    /**
     * The token expiration date time
     *
     * @var int
     */
    private $expireAt;

    /**
     * The refresh token
     *
     * @var string
     */
    private $refreshToken;

    /**
     * The scopes
     *
     * @var string[]
     */
    private $scopes;

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
        $this->lifetime = (int)$lifetime;
        $this->expireAt = time() + $this->lifetime;
        $this->accessToken = $accessToken;
        $this->tokenType = $tokenType;
        $this->refreshToken = $refreshToken;
        $this->scopes = $scopes;
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
     * Get the token type
     *
     * @return string
     */
    public function tokenType()
    {
        return $this->tokenType;
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
     * Get the refresh token
     *
     * @return string
     */
    public function refreshToken()
    {
        return $this->refreshToken;
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
        return $this->lifetime !== -1 && $this->expireAt <= (time() + $delta);
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