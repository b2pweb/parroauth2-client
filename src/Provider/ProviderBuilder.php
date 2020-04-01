<?php

namespace Parroauth2\Client\Provider;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;

/**
 * Builder for manual configuration of Provider
 *
 * @see https://openid.net/specs/openid-connect-discovery-1_0.html
 * @see https://tools.ietf.org/html/rfc8414
 */
final class ProviderBuilder
{
    /**
     * @var ProviderLoader
     */
    private $loader;

    /**
     * @var ProviderConfigPool
     */
    private $configPool;

    /**
     * @var string
     */
    private $url;

    /**
     * @var array
     */
    private $config = [];

    /**
     * @var bool
     */
    private $openid = false;


    /**
     * ProviderBuilder constructor.
     *
     * @param ProviderLoader $loader
     * @param ProviderConfigPool $configPool
     * @param string $url The base provider URL
     *
     * @internal Use ProviderLoader::builder() for instantiate the builder
     */
    public function __construct(ProviderLoader $loader, ProviderConfigPool $configPool, string $url)
    {
        $this->loader = $loader;
        $this->configPool = $configPool;
        $this->url = $url;
    }

    /**
     * Configure an endpoint URI
     *
     * <code>
     * $builder
     *     ->endPoint('authorization', '/authorize')
     *     ->endPoint('token', 'https://op.example.com/token')
     * ;
     * </code>
     *
     * @param string $name The endpoint name. Should be in lower case
     * @param string $url The endpoint URI. Can be relative or absolute
     *
     * @return $this
     */
    public function endPoint(string $name, string $url): self
    {
        // Relative URI : use the base URL
        if (strpos($url, 'http://') === false && strpos($url, 'https://') === false) {
            $url = rtrim($this->url, '/').'/'.ltrim($url, '/');
        }

        $this->config[$name.'_endpoint'] = $url;

        return $this;
    }

    /**
     * Configure multiple endpoints
     *
     * <code>
     * $builder->endPoints([
     *     'authorization' => '/authorize',
     *     'token' => 'https://op.example.com/token',
     * ]);
     * </code>
     *
     * @param string[] $endPoints Endpoints map, with key as name, and uri as value
     *
     * @return $this
     */
    public function endPoints(array $endPoints): self
    {
        foreach ($endPoints as $name => $uri) {
            $this->endPoint($name, $uri);
        }

        return $this;
    }

    /**
     * Define the authorization endpoint
     *
     * @param string $uri The endpoint URI. Can be relative or absolute
     *
     * @return $this
     */
    public function authorizationEndPoint(string $uri): self
    {
        return $this->endPoint('authorization', $uri);
    }

    /**
     * Define the token endpoint
     *
     * @param string $uri The endpoint URI. Can be relative or absolute
     *
     * @return $this
     */
    public function tokenEndPoint(string $uri): self
    {
        return $this->endPoint('token', $uri);
    }

    /**
     * Define the revocation endpoint
     *
     * @param string $uri The endpoint URI. Can be relative or absolute
     *
     * @return $this
     */
    public function revocationEndPoint(string $uri): self
    {
        return $this->endPoint('revocation', $uri);
    }

    /**
     * Define the introspection endpoint
     *
     * @param string $uri The endpoint URI. Can be relative or absolute
     *
     * @return $this
     */
    public function introspectionEndPoint(string $uri): self
    {
        return $this->endPoint('introspection', $uri);
    }

    /**
     * Define an option
     *
     * @param string $name The option name
     * @param mixed $value The value
     *
     * @return $this
     *
     * @see https://openid.net/specs/openid-connect-discovery-1_0.html The OpenID Connect options
     * @see https://tools.ietf.org/html/rfc8414 The OAuth 2.0 options
     */
    public function option(string $name, $value): self
    {
        $this->config[$name] = $value;

        return $this;
    }

    /**
     * Define the JWKSet
     *
     * @param JWK|JWK[]|JWKSet $keys
     *
     * @return $this
     */
    public function keySet($keys): self
    {
        switch (true) {
            case $keys instanceof JWKSet:
            case is_array($keys):
                $this->config['jwks'] = $keys;
                break;

            case $keys instanceof JWK:
                $this->config['jwks'] = [$keys];
                break;

            default:
                throw new \TypeError('$keys must be of type JWKSet, array or JWK');
        }

        return $this;
    }

    /**
     * Add a new key to the key set
     *
     * @param JWK $key
     *
     * @return $this
     */
    public function addKey(JWK $key): self
    {
        if (empty($this->config['jwks'])) {
            $this->config['jwks'] = [$key];
        } elseif (is_array($this->config['jwks'])) {
            $this->config['jwks'][] = $key;
        } elseif ($this->config['jwks'] instanceof JWKSet) {
            $this->config['jwks'] = $this->config['jwks']->with($key);
        } else {
            $this->config['jwks'] = [$key];
        }

        return $this;
    }

    /**
     * Add a new RSA key file to the key set
     *
     * @param string $file The RSA key filename
     * @param string|null $password Password of the file
     * @param array $additionalValues
     *
     * @return $this
     * @throws \Exception
     *
     * @see JWKFactory::createFromKeyFile()
     */
    public function addKeyFile(string $file, ?string $password = null, array $additionalValues = []): self
    {
        return $this->addKey(JWKFactory::createFromKeyFile($file, $password, $additionalValues));
    }

    /**
     * The provider supports OpenID Connect
     *
     * @return $this
     */
    public function openid(): self
    {
        $this->openid = true;

        return $this;
    }

    /**
     * The provider is a simple OAuth2 server
     *
     * @return $this
     */
    public function oauth2(): self
    {
        $this->openid = false;

        return $this;
    }

    /**
     * Build the provider
     *
     * @return ProviderInterface
     */
    public function create(): ProviderInterface
    {
        if (isset($this->config['issuer'])) {
            $this->config['issuer'] = $this->url;
        }

        if (!empty($this->config['jwks'])) {
            if (is_array($this->config['jwks'])) {
                $this->config['jwks'] = new JWKSet($this->config['jwks']);
            } elseif (!$this->config['jwks'] instanceof JWKSet) {
                throw new InvalidArgumentException('Invalid jwks option : must be a JWKSet or an array');
            }
        }

        return $this->loader->create($this->configPool->create($this->url, $this->config, $this->openid));
    }
}
