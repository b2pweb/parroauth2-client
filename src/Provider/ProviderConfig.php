<?php

namespace Parroauth2\Client\Provider;

use Psr\SimpleCache\CacheInterface;

/**
 * Store the configuration of a provider
 *
 * Note: Do not creates directly, use ProviderConfigPool::create methods instead
 */
final class ProviderConfig implements \ArrayAccess
{
    /**
     * @var string
     */
    private $url;

    /**
     * @var array
     */
    private $config;

    /**
     * @var bool
     */
    private $openid;

    /**
     * @var CacheInterface|null
     */
    private $cache;


    /**
     * @internal Use ProviderConfigPool create instead
     *
     * @param string $url
     * @param array $config
     * @param bool $openid
     */
    public function __construct(string $url, array $config, bool $openid)
    {
        $this->url = $url;
        $this->config = $config;
        $this->openid = $openid;
    }

    /**
     * @return string
     */
    public function url(): string
    {
        return $this->url;
    }

    /**
     * @return array
     */
    public function config(): array
    {
        return $this->config;
    }

    /**
     * @return bool
     */
    public function openid(): bool
    {
        return $this->openid;
    }

    /**
     * {@inheritdoc}
     */
    public function offsetExists($offset)
    {
        return isset($this->config[$offset]);
    }

    /**
     * {@inheritdoc}
     */
    public function offsetGet($offset)
    {
        return $this->config[$offset];
    }

    /**
     * {@inheritdoc}
     */
    public function offsetSet($offset, $value)
    {
        $this->config[$offset] = $value;
        $this->save();
    }

    /**
     * {@inheritdoc}
     */
    public function offsetUnset($offset)
    {
        unset($this->config[$offset]);
    }

    /**
     * @param CacheInterface|null $cache
     * @internal
     */
    public function setCache(?CacheInterface $cache): void
    {
        $this->cache = $cache;
    }

    /**
     * Save the config into cache
     */
    public function save(): void
    {
        if ($this->cache) {
            $this->cache->set(ProviderConfigPool::urlToKey($this->url), $this);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function __sleep()
    {
        // Ignore cache
        return ['url', 'config', 'openid'];
    }
}
