<?php

namespace Parroauth2\Client;

use DateTime;

/**
 * Class Grant
 *
 * @package Parroauth2\Client
 */
class Grant
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
     * @var string
     */
    protected $type;

    /**
     * Grant constructor.
     *
     * @param string $access
     * @param DateTime $validityEndpoint
     * @param string $type
     */
    public function __construct($access, $validityEndpoint, $refresh, $type)
    {
        $this->access = $access;
        $this->validityEndpoint = $validityEndpoint;
        $this->refresh = $refresh;
        $this->type = $type;
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
}