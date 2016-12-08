<?php

namespace Parroauth2\Client;

use Parroauth2\Client\Credentials\ClientCredentials;

/**
 * Request
 */
class Request
{
    /**
     * The request query parameters
     *
     * @var array
     */
    protected $queries = [];

    /**
     * The request post parameters
     *
     * @var array
     */
    protected $attributes = [];

    /**
     * The request headers
     *
     * @var array
     */
    protected $headers = [];

    /**
     * The app client credentials
     *
     * @var ClientCredentials
     */
    protected $credentials;

    /**
     * Request constructor.
     * 
     * @param array $queries
     * @param array $attributes
     * @param null|ClientCredentials $credentials
     */
    public function __construct(array $queries = [], array $attributes = [], ClientCredentials $credentials = null)
    {
        $this->queries = $queries;
        $this->attributes = $attributes;
        $this->credentials = $credentials;

        if ($credentials !== null) {
            $credentials->prepare($this);
        }
    }

    /**
     * Add query parameters
     *
     * @param array $queries
     *
     * @return $this
     */
    public function addQueries(array $queries)
    {
        $this->queries += $queries;

        return $this;
    }

    /**
     * Add query parameter
     *
     * @param string $key
     * @param string $value
     *
     * @return $this
     */
    public function addQuery($key, $value)
    {
        $this->queries[$key] = $value;

        return $this;
    }

    /**
     * Get the query parameters
     *
     * @return array
     */
    public function queries()
    {
        return $this->queries;
    }

    /**
     * Get a query parameter
     *
     * @param string $key
     * @param string $default
     *
     * @return array
     */
    public function query($key, $default = null)
    {
        if (!isset($this->queries[$key])) {
            return $default;
        }

        return $this->queries[$key];
    }

    /**
     * Add post parameters
     *
     * @param array $attributes
     *
     * @return $this
     */
    public function addAttributes(array $attributes)
    {
        $this->attributes += $attributes;

        return $this;
    }

    /**
     * Add post parameter
     *
     * @param string $key
     * @param string $value
     *
     * @return $this
     */
    public function addAttribute($key, $value)
    {
        $this->attributes[$key] = $value;

        return $this;
    }

    /**
     * Get the post parameters
     *
     * @return array
     */
    public function attributes()
    {
        return $this->attributes;
    }

    /**
     * Get a post parameter
     *
     * @param string $key
     * @param mixed  $default
     *
     * @return array
     */
    public function attribute($key, $default = null)
    {
        if (!isset($this->attributes[$key])) {
            return $default;
        }

        return $this->attributes[$key];
    }

    /**
     * Add headers
     *
     * @param array $headers
     *
     * @return $this
     */
    public function addHeaders(array $headers)
    {
        $this->headers += $headers;

        return $this;
    }

    /**
     * Get the request headers
     *
     * @return array
     */
    public function headers()
    {
        return $this->headers;
    }

    /**
     * Get a header from key
     *
     * @todo Gerer un format unique des headers
     *
     * @param string $key
     * @param mixed  $default
     *
     * @return array
     */
    public function header($key, $default = null)
    {
        if (!isset($this->headers[$key])) {
            return $default;
        }

        return $this->headers[$key];
    }

    /**
     * Get the request credentials
     *
     * @return null|ClientCredentials
     */
    public function credentials()
    {
        return $this->credentials;
    }
}