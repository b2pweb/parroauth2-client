<?php

namespace Parroauth2\Client\Authentication;

use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Request;
use Parroauth2\Client\ClientConfig;
use Parroauth2\Client\Tests\UnitTestCase;

class RequestBodyClientAuthenticationMethodTest extends UnitTestCase
{
    public function test_without_secret()
    {
        $method = new RequestBodyClientAuthenticationMethod(new Psr17Factory());
        $client = $this->provider()->client((new ClientConfig('my_client')));

        $request = $method->apply($client, new Request('GET', 'http://foo.com'));

        $this->assertEquals('client_id=my_client', (string) $request->getBody());
    }

    public function test_with_secret()
    {
        $method = new RequestBodyClientAuthenticationMethod(new Psr17Factory());
        $client = $this->provider()->client((new ClientConfig('my_client'))->setSecret('my-secret'));

        $request = $method->apply($client, new Request('GET', 'http://foo.com'));

        $this->assertEquals('client_id=my_client&client_secret=my-secret', (string) $request->getBody());
    }

    public function test_with_body()
    {
        $method = new RequestBodyClientAuthenticationMethod(new Psr17Factory());
        $client = $this->provider()->client((new ClientConfig('my_client'))->setSecret('my-secret'));

        $request = $method->apply($client, (new Request('GET', 'http://foo.com'))->withBody((new Psr17Factory())->createStream('foo=bar&baz=qux')));

        $this->assertEquals('foo=bar&baz=qux&client_id=my_client&client_secret=my-secret', (string) $request->getBody());
    }

    public function test_withSigningAlgorithms()
    {
        $method = new RequestBodyClientAuthenticationMethod(new Psr17Factory());
        $this->assertSame($method, $method->withSigningAlgorithms(['HS256']));
    }

    public function test_name()
    {
        $method = new RequestBodyClientAuthenticationMethod(new Psr17Factory());
        $this->assertSame('client_secret_post', $method->name());
    }
}
