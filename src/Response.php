<?php

namespace Parroauth2\Client;

/**
 * Response
 */
class Response
{
    /**
     * @var array
     */
    protected $body;

    /**
     * Response constructor.
     * 
     * @param array $body
     */
    public function __construct(array $body = [])
    {
        $this->body = $body;
    }

    /**
     * @param array $body
     * 
     * @return Response
     */
    public function setBody(array $body)
    {
        $this->body = $body;

        return $this;
    }

    /**
     * @return array
     */
    public function getBody()
    {
        return $this->body;
    }

    /**
     * @param string $key
     *
     * @return mixed
     */
    public function hasBodyItem($key)
    {
        return isset($this->body[$key]);
    }

    /**
     * @param string $key
     * @param mixed $default
     *
     * @return mixed
     */
    public function getBodyItem($key, $default = null)
    {
        if (!$this->hasBodyItem($key)) {
            return $default;
        }

        return $this->body[$key];
    }
}