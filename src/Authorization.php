<?php

namespace Parroauth2\Client;

/**
 * Class Authorization
 */
class Authorization
{
    /**
     * @var string
     */
    protected $access;

    /**
     * @var string
     */
    protected $type;

    /**
     * @var int
     */
    protected $lifetime;

    /**
     * @var string
     */
    protected $refresh;

    /**
     * @var string[]
     */
    protected $scopes;

    /**
     * Authorization constructor.
     *
     * @param string $access
     * @param string $type
     * @param int $lifetime
     * @param string $refresh
     * @param string[] $scopes
     */
    public function __construct($access, $type, $lifetime = null, $refresh = '', array $scopes = [])
    {
        $this->access = $access;
        $this->type = $type;
        $this->lifetime = $lifetime;
        $this->refresh = $refresh;
        $this->scopes = $scopes;
    }

    /**
     * @param string $access
     */
    public function setAccess($access)
    {
        $this->access = $access;
    }

    /**
     * @return string
     */
    public function getAccess()
    {
        return $this->access;
    }

    /**
     * @param string $type
     */
    public function setType($type)
    {
        $this->type = $type;
    }

    /**
     * @return string
     */
    public function getType()
    {
        return $this->type;
    }

    /**
     * @param int $lifetime
     */
    public function setLifetime($lifetime)
    {
        $this->lifetime = $lifetime;
    }

    /**
     * @return int
     */
    public function getLifetime()
    {
        return $this->lifetime;
    }

    /**
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
     * @param string $refresh
     */
    public function setRefresh($refresh)
    {
        $this->refresh = $refresh;
    }

    /**
     * @return string
     */
    public function getRefresh()
    {
        return $this->refresh;
    }

    /**
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
     * @return string[]
     */
    public function getScopes()
    {
        return $this->scopes;
    }

    /**
     * @param $scope
     *
     * @return bool
     */
    public function hasScope($scope)
    {
        return in_array($scope, $this->scopes);
    }
}