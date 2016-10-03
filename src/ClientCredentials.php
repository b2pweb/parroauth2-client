<?php

namespace Parroauth2\Client;

/**
 * Class ClientCredentials
 *
 * @package Parroauth2\Client
 */
class ClientCredentials
{
    /**
     * @var string
     */
    protected $id;

    /**
     * @var string
     */
    protected $secret;

    /**
     * ClientCredentials constructor.
     *
     * @param string $id
     * @param string $secret
     */
    public function __construct($id, $secret)
    {
        $this->id = $id;
        $this->secret = $secret;
    }

    /**
     * @param string $id
     *
     * @return ClientCredentials
     */
    public function setId($id)
    {
        $this->id = $id;

        return $this;
    }

    /**
     * @return string
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * @param string $secret
     *
     * @return ClientCredentials
     */
    public function setSecret($secret)
    {
        $this->secret = $secret;

        return $this;
    }

    /**
     * @return string
     */
    public function getSecret()
    {
        return $this->secret;
    }
}