<?php

namespace Parroauth2\Client\Provider;

use Psr\SimpleCache\CacheInterface;

/**
 * Cache pool for provider configurations
 */
final class ProviderConfigPool
{
    /**
     * @var CacheInterface|null
     */
    private $cache;

    /**
     * Default provider config to apply
     *
     * @var array<string, mixed>
     */
    private $defaults;

    /**
     * ProviderConfigPool constructor.
     *
     * @param CacheInterface|null $cache The cache system. If null the cache is disabled
     * @param array<string, mixed> $defaults Default provider config to apply
     */
    public function __construct(?CacheInterface $cache = null, array $defaults = [])
    {
        $this->cache = $cache;
        $this->defaults = $defaults;
    }

    /**
     * Get a provider config from the cache pool
     *
     * @param string $url The provider URL
     *
     * @return ProviderConfig|null The cached config, or null if not in cache
     */
    public function get(string $url): ?ProviderConfig
    {
        if (!$this->cache) {
            return null;
        }

        $config = $this->cache->get(self::urlToKey($url));

        if (!$config instanceof ProviderConfig) {
            return null;
        }

        $config->setCache($this->cache);

        return $config;
    }

    /**
     * Creates the provider config
     *
     * @param string $url The provider URL
     * @param array<string, mixed> $config The config data
     * @param bool $openid Does the provider is an OpenID connect provider ?
     *
     * @return ProviderConfig
     */
    public function create(string $url, array $config, bool $openid): ProviderConfig
    {
        $config = new ProviderConfig($url, $config + $this->defaults, $openid);
        $config->setCache($this->cache);

        return $config;
    }

    /**
     * Creates the provider config from the config array
     * Use issuer as URL
     *
     * @param array<string, mixed> $config The provider config
     * @param bool|null $openid Does the provider is an OpenID connect provider ?
     *     If null, try to detect is it's an OpenID config
     *
     * @return ProviderConfig
     */
    public function createFromArray(array $config, ?bool $openid = null): ProviderConfig
    {
        if ($openid === null) {
            $openid = !empty($config['userinfo_endpoint']);
        }

        return $this->create($config['issuer'] ?? '', $config, $openid);
    }

    /**
     * Creates the provider config from a JSON object
     *
     * @param string $url The provider URL
     * @param string $config The JSON config
     * @param bool $openid Does the provider is an OpenID connect provider
     *
     * @return ProviderConfig
     */
    public function createFromJson(string $url, string $config, bool $openid): ProviderConfig
    {
        return $this->create($url, (array) json_decode($config, true), $openid);
    }

    /**
     * Convert an URL to a cache key
     *
     * @param string $url The provider URL
     *
     * @return string
     */
    public static function urlToKey(string $url): string
    {
        return hash('sha256', $url);
    }
}
