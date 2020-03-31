<?php

namespace Parroauth2\Client\Provider;

use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use Parroauth2\Client\Factory\BaseClientFactory;
use Parroauth2\Client\Tests\UnitTestCase;

/**
 * Class ProviderBuilderTest
 */
class ProviderBuilderTest  extends UnitTestCase
{
    /**
     * @var ProviderBuilder
     */
    private $builder;

    protected function setUp(): void
    {
        parent::setUp();

        $this->builder = (new ProviderLoader(new BaseClientFactory($this->session), $this->httpClient))->builder('http://op.example.com');
    }

    /**
     *
     */
    public function test_create_default()
    {
        $provider = $this->builder->create();

        $this->assertEquals('http://op.example.com', $provider->issuer());
        $this->assertFalse($provider->openid());
    }

    /**
     *
     */
    public function test_endPoint_relative_uri()
    {
        $this->assertEquals('http://op.example.com/bar', $this->builder->endPoint('foo', '/bar')->create()->uri('foo'));
    }

    /**
     *
     */
    public function test_endPoint_absolute_uri()
    {
        $this->assertEquals('http://foo.example.com/', $this->builder->endPoint('foo', 'http://foo.example.com/')->create()->uri('foo'));
    }

    /**
     *
     */
    public function test_endPoints()
    {
        $provider = $this->builder->endPoints([
            'foo' => '/foo',
            'bar' => 'http://bar.example.com'
        ])->create();

        $this->assertEquals('http://op.example.com/foo', $provider->uri('foo'));
        $this->assertEquals('http://bar.example.com', $provider->uri('bar'));
    }

    /**
     *
     */
    public function test_authorizationEndPoint()
    {
        $this->assertEquals('http://op.example.com/authorize', $this->builder->authorizationEndPoint('/authorize')->create()->uri('authorization'));
    }

    /**
     *
     */
    public function test_tokenEndPoint()
    {
        $this->assertEquals('http://op.example.com/token', $this->builder->tokenEndPoint('/token')->create()->uri('token'));
    }

    /**
     *
     */
    public function test_revocationEndPoint()
    {
        $this->assertEquals('http://op.example.com/revoke', $this->builder->revocationEndPoint('/revoke')->create()->uri('revocation'));
    }

    /**
     *
     */
    public function test_introspectionEndPoint()
    {
        $this->assertEquals('http://op.example.com/introspect', $this->builder->introspectionEndPoint('/introspect')->create()->uri('introspection'));
    }

    /**
     *
     */
    public function test_option()
    {
        $this->assertEquals('bar', $this->builder->option('foo', 'bar')->create()->metadata('foo'));
    }

    /**
     *
     */
    public function test_openid()
    {
        $this->assertTrue($this->builder->openid()->create()->openid());
        $this->assertFalse($this->builder->oauth2()->create()->openid());
    }

    /**
     *
     */
    public function test_addKeyFile()
    {
        $keys = $this->builder->addKeyFile(__DIR__.'/../../keys/oauth-public.key')->create()->keySet();

        $this->assertCount(1, $keys);
        $this->assertEquals('RSA', $keys->get(0)->get('kty'));
    }

    /**
     *
     */
    public function test_keySet_array()
    {
        $keys = $this->builder->keySet([JWKFactory::createFromSecret('secret')])->create()->keySet();

        $this->assertEquals($keys, new JWKSet([JWKFactory::createFromSecret('secret')]));
    }

    /**
     *
     */
    public function test_keySet_JWKSet()
    {
        $keySet = new JWKSet([JWKFactory::createFromSecret('secret')]);
        $this->assertSame($keySet, $this->builder->keySet($keySet)->create()->keySet());
    }

    /**
     *
     */
    public function test_keySet_JWK()
    {
        $key = JWKFactory::createFromSecret('secret');
        $keys = $this->builder->keySet($key)->create()->keySet();

        $this->assertEquals($keys, new JWKSet([$key]));
    }

    /**
     *
     */
    public function test_keySet_invalid_type()
    {
        $this->expectException(\TypeError::class);
        $this->builder->keySet('invalid');
    }

    /**
     *
     */
    public function test_addKey_from_empty_jwks()
    {
        $this->assertEquals(new JWKSet([JWKFactory::createFromSecret('secret')]), $this->builder->addKey(JWKFactory::createFromSecret('secret'))->create()->keySet());
    }

    /**
     *
     */
    public function test_addKey_multiple()
    {
        $this->assertEquals(new JWKSet([
            JWKFactory::createFromSecret('foo'),
            JWKFactory::createFromSecret('bar'),
            JWKFactory::createFromSecret('baz'),
        ]),
            $this->builder
                ->addKey(JWKFactory::createFromSecret('foo'))
                ->addKey(JWKFactory::createFromSecret('bar'))
                ->addKey(JWKFactory::createFromSecret('baz'))
                ->create()->keySet()
        );
    }

    /**
     *
     */
    public function test_addKey_from_JWKSet()
    {
        $this->assertEquals(
            new JWKSet([
                JWKFactory::createFromSecret('foo'),
                JWKFactory::createFromSecret('bar'),
            ]),
            $this->builder
                ->keySet(new JWKSet([JWKFactory::createFromSecret('foo')]))
                ->addKey(JWKFactory::createFromSecret('bar'))
                ->create()->keySet()
        );
    }
}
