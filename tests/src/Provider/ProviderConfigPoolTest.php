<?php

namespace Parroauth2\Client\Provider;

use Cache\Adapter\PHPArray\ArrayCachePool;
use PHPUnit\Framework\TestCase;

/**
 * Class ProviderConfigPoolTest
 */
class ProviderConfigPoolTest extends TestCase
{
    /**
     *
     */
    public function test_get_without_cache_should_return_null()
    {
        $this->assertNull((new ProviderConfigPool())->get('http://op.example.com'));
    }

    /**
     *
     */
    public function test_get_with_cache_miss_should_return_null()
    {
        $pool = new ProviderConfigPool(new ArrayCachePool());

        $this->assertNull($pool->get('http://op.example.com'));
    }

    /**
     *
     */
    public function test_get_with_invalid_cache_data_should_return_null()
    {
        $pool = new ProviderConfigPool($cache = new ArrayCachePool());
        $cache->set(ProviderConfigPool::urlToKey('http://op.example.com'), 'invalid data');

        $this->assertNull($pool->get('http://op.example.com'));
    }

    /**
     *
     */
    public function test_get_from_cache()
    {
        $pool = new ProviderConfigPool(new ArrayCachePool());
        $config = $pool->create('http://op.example.com', [], true);
        $config->save();

        $this->assertEquals($config, $pool->get('http://op.example.com'));
    }

    /**
     *
     */
    public function test_create()
    {
        $pool = new ProviderConfigPool(new ArrayCachePool());

        $config = $pool->create('http://op.example.com', ['foo' => 'bar'], true);

        $this->assertInstanceOf(ProviderConfig::class, $config);
        $this->assertEquals('http://op.example.com', $config->url());
        $this->assertEquals('bar', $config['foo']);
        $this->assertTrue($config->openid());
    }

    /**
     *
     */
    public function test_create_with_defaults()
    {
        $pool = new ProviderConfigPool(new ArrayCachePool(), ['my_param' => 'default_value']);

        $config = $pool->create('http://op.example.com', ['foo' => 'bar'], true);

        $this->assertInstanceOf(ProviderConfig::class, $config);
        $this->assertEquals('http://op.example.com', $config->url());
        $this->assertEquals('bar', $config['foo']);
        $this->assertEquals('default_value', $config['my_param']);
        $this->assertTrue($config->openid());

        $config = $pool->create('http://op.example.com', ['foo' => 'bar', 'my_param' => 'other'], true);

        $this->assertInstanceOf(ProviderConfig::class, $config);
        $this->assertEquals('http://op.example.com', $config->url());
        $this->assertEquals('bar', $config['foo']);
        $this->assertEquals('other', $config['my_param']);
        $this->assertTrue($config->openid());
    }

    /**
     *
     */
    public function test_createFromArray()
    {
        $pool = new ProviderConfigPool(new ArrayCachePool());

        $config = $pool->createFromArray(['issuer' => 'http://op.example.com', 'foo' => 'bar'], true);

        $this->assertInstanceOf(ProviderConfig::class, $config);
        $this->assertEquals('http://op.example.com', $config->url());
        $this->assertEquals('bar', $config['foo']);
        $this->assertTrue($config->openid());

        $this->assertFalse($pool->createFromArray(['issuer' => 'http://op.example.com'])->openid());
        $this->assertTrue($pool->createFromArray(['issuer' => 'http://op.example.com', 'userinfo_endpoint' => 'http://op.example.com/userinfo'])->openid());
    }

    /**
     *
     */
    public function test_createFromJson()
    {
        $pool = new ProviderConfigPool(new ArrayCachePool());

        $config = $pool->createFromJson('http://op.example.com', '{"foo":"bar"}', true);

        $this->assertInstanceOf(ProviderConfig::class, $config);
        $this->assertEquals('http://op.example.com', $config->url());
        $this->assertEquals('bar', $config['foo']);
        $this->assertTrue($config->openid());
    }
}
