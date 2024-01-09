<?php

namespace Parroauth2\Client\Authentication;

use Nyholm\Psr7\Request;
use Parroauth2\Client\ClientConfig;
use Parroauth2\Client\Tests\UnitTestCase;

class BasicClientAuthenticationMethodTest extends UnitTestCase
{
    public function test_without_secret()
    {
        $method = new BasicClientAuthenticationMethod();
        $client = $this->provider()->client((new ClientConfig('my_client')));

        $request = $method->apply($client, new Request('GET', 'http://foo.com'));

        $this->assertSame('Basic bXlfY2xpZW50Og==', $request->getHeaderLine('Authorization'));
    }

    public function test_with_secret()
    {
        $method = new BasicClientAuthenticationMethod();
        $client = $this->provider()->client((new ClientConfig('my_client'))->setSecret('my-secret'));

        $request = $method->apply($client, new Request('GET', 'http://foo.com'));

        $this->assertSame('Basic bXlfY2xpZW50Om15LXNlY3JldA==', $request->getHeaderLine('Authorization'));
    }

    public function test_withSigningAlgorithms()
    {
        $method = new BasicClientAuthenticationMethod();
        $this->assertSame($method, $method->withSigningAlgorithms(['HS256']));
    }

    public function test_name()
    {
        $method = new BasicClientAuthenticationMethod();
        $this->assertSame('client_secret_basic', $method->name());
    }
}
