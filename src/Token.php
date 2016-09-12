<?php

namespace Parroauth2\Client;

use DateTime;

/**
 * Class Token
 *
 * @package Parroauth2\Client
 */
class Token
{
    /**
     * @var string
     */
    protected $access;

    /**
     * @var DateTime
     */
    protected $validityEndpoint;

    /**
     * @var string
     */
    protected $refresh;

    /**
     * Token constructor.
     *
     * @param string $access
     * @param DateTime $validityEndpoint
     * @param string $refresh
     */
    public function __construct($access, $validityEndpoint, $refresh)
    {
        $this->access = $access;
        $this->validityEndpoint = $validityEndpoint;
        $this->refresh = $refresh;
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
     * @param DateTime $validityEndpoint
     */
    public function setValidityEndpoint($validityEndpoint)
    {
        $this->validityEndpoint = $validityEndpoint;
    }

    /**
     * @return DateTime
     */
    public function getValidityEndpoint()
    {
        return $this->validityEndpoint;
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
     * @return bool
     */
    public function isExpired()
    {
        return time() >= $this->validityEndpoint->getTimestamp();
    }
}