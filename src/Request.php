<?php

namespace Parroauth2\Client;

/**
 * Class Request
 */
class Request
{
    /**
     * @var array
     */
    protected $parameters = [];

    /**
     * @var ClientCredentials
     */
    protected $credentials = [];

    /**
     * Request constructor.
     * 
     * @param array $parameters
     * @param null $credentials
     */
    public function __construct($parameters = [], $credentials = null)
    {
        $this->parameters = $parameters;
        $this->credentials = $credentials;
    }

    /**
     * @param array $parameters
     *
     * @return $this
     */
    public function setParameters($parameters)
    {
        $this->parameters = $parameters;

        return $this;
    }

    /**
     * @param string $key
     * @param string $value
     *
     * @return $this
     */
    public function setParameter($key, $value)
    {
        $this->parameters[$key] = $value;

        return $this;
    }

    /**
     * @param array $parameters
     *
     * @return $this
     */
    public function addParameters($parameters)
    {
        $this->parameters += $parameters;

        return $this;
    }

    /**
     * @return array
     */
    public function getParameters()
    {
        return $this->parameters;
    }

    /**
     * @param string $key
     * @param string $value
     *
     * @return array
     */
    public function getParameter($key, $value = null)
    {
        if (!isset($this->parameters[$key])) {
            return $value;
        }

        return $this->parameters[$key];
    }

    /**
     * @param ClientCredentials $credentials
     *
     * @return Request
     */
    public function setCredentials($credentials)
    {
        $this->credentials = $credentials;

        return $this;
    }

    /**
     * @return ClientCredentials
     */
    public function getCredentials()
    {
        return $this->credentials;
    }
}