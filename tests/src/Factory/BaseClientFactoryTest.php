<?php

namespace Parroauth2\Client\Factory;

use Parroauth2\Client\ClientConfig;
use Parroauth2\Client\EndPoint\Authorization\AuthorizationEndPoint;
use Parroauth2\Client\EndPoint\Introspection\IntrospectionEndPoint;
use Parroauth2\Client\EndPoint\Token\RevocationEndPoint;
use Parroauth2\Client\EndPoint\Token\TokenEndPoint;
use Parroauth2\Client\OpenID\EndPoint\EndSessionEndPoint;
use Parroauth2\Client\OpenID\EndPoint\Userinfo\UserinfoEndPoint;
use Parroauth2\Client\Tests\UnitTestCase;

/**
 * Class BaseClientFactoryTest
 */
class BaseClientFactoryTest extends UnitTestCase
{
    /**
     *
     */
    public function test_create_oauth()
    {
        $provider = $this->provider([], false);
        $factory = new BaseClientFactory();
        $client = $factory->create($provider, (new ClientConfig('test')));

        $this->assertSame($factory->storage(), $client->storage());
        $this->assertSame($provider, $client->provider());
        $this->assertEquals('test', $client->clientId());

        $this->assertEquals(AuthorizationEndPoint::class, get_class($client->endPoints()->authorization()));
        $this->assertEquals(TokenEndPoint::class, get_class($client->endPoints()->token()));
        $this->assertEquals(RevocationEndPoint::class, get_class($client->endPoints()->revocation()));
        $this->assertEquals(IntrospectionEndPoint::class, get_class($client->endPoints()->introspection()));
    }

    /**
     *
     */
    public function test_create_openid()
    {
        $provider = $this->provider();
        $factory = new BaseClientFactory();
        $client = $factory->create($provider, (new ClientConfig('test')));

        $this->assertSame($factory->storage(), $client->storage());
        $this->assertSame($provider, $client->provider());
        $this->assertEquals('test', $client->clientId());

        $this->assertEquals(\Parroauth2\Client\OpenID\EndPoint\AuthorizationEndPoint::class, get_class($client->endPoints()->authorization()));
        $this->assertEquals(\Parroauth2\Client\OpenID\EndPoint\Token\TokenEndPoint::class, get_class($client->endPoints()->token()));
        $this->assertEquals(RevocationEndPoint::class, get_class($client->endPoints()->revocation()));
        $this->assertEquals(IntrospectionEndPoint::class, get_class($client->endPoints()->introspection()));
        $this->assertEquals(UserinfoEndPoint::class, get_class($client->endPoints()->userinfo()));
        $this->assertEquals(EndSessionEndPoint::class, get_class($client->endPoints()->endSession()));
    }
}
