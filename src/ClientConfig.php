<?php

namespace Parroauth2\Client;

/**
 * Configuration of the client
 *
 * Note: It's not recommended to modify the options once the client is created
 *
 * @see Client
 */
class ClientConfig
{
    /**
     * @var string
     */
    private $clientId;

    /**
     * @var string
     */
    private $secret;

    /**
     * @var bool
     */
    private $openid = true;

    /**
     * @var string[]
     */
    private $scopes = [];

    /**
     * @var array
     */
    private $options = [];


    /**
     * ClientConfig constructor.
     *
     * @param string $clientId
     */
    public function __construct(string $clientId)
    {
        $this->clientId = $clientId;
    }

    /**
     * Get the client id
     * Must match with the client id configuration on the provider side
     *
     * @return string
     */
    public function clientId(): string
    {
        return $this->clientId;
    }

    /**
     * Get the client secret
     * This value may be null for a public client
     *
     * @return string
     */
    public function secret(): ?string
    {
        return $this->secret;
    }

    /**
     * Set the client secret
     *
     * @param string $secret
     *
     * @return $this
     */
    public function setSecret(string $secret): ClientConfig
    {
        $this->secret = $secret;

        return $this;
    }

    /**
     * Does openid connect is enabled for the client ?
     * Note: This configuration has no effect on provided which do not supports openid connect
     *
     * @return bool
     */
    public function openid(): bool
    {
        return $this->openid;
    }

    /**
     * Enable (or disable) openid for the client
     *
     * @param bool $flag
     *
     * @return $this
     */
    public function enableOpenId(bool $flag = true): ClientConfig
    {
        $this->openid = $flag;

        return $this;
    }

    /**
     * Get the configured scopes
     *
     * @return string[]
     */
    public function scopes(): array
    {
        return $this->scopes;
    }

    /**
     * Configure the client scopes
     * Adding openid scope is not required
     *
     * @param string[] $scopes
     *
     * @return $this
     */
    public function setScopes(array $scopes): ClientConfig
    {
        $this->scopes = $scopes;

        return $this;
    }

    /**
     * Get a client option
     *
     * @param string $name The option name
     * @param mixed $default The default value, if not set on the config
     *
     * @return mixed
     */
    public function option(string $name, $default = null)
    {
        return $this->options[$name] ?? $default;
    }

    /**
     * Set a client option
     *
     * @param string $name The option name
     * @param mixed $value The option value
     *
     * @return $this
     */
    public function setOption(string $name, $value): ClientConfig
    {
        $this->options[$name] = $value;

        return $this;
    }
}
