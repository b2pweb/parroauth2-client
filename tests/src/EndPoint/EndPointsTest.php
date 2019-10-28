<?php

namespace Parroauth2\Client\EndPoint;

use Parroauth2\Client\Client;
use Parroauth2\Client\ClientConfig;
use Parroauth2\Client\EndPoint\Authorization\AuthorizationEndPoint;
use Parroauth2\Client\EndPoint\Introspection\IntrospectionEndPoint;
use Parroauth2\Client\EndPoint\Token\RevocationEndPoint;
use Parroauth2\Client\EndPoint\Token\TokenEndPoint;
use Parroauth2\Client\Extension\Pkce;
use Parroauth2\Client\OpenID\EndPoint\Userinfo\UserinfoEndPoint;
use Parroauth2\Client\Tests\UnitTestCase;

/**
 * Class EndPointsTest
 */
class EndPointsTest extends UnitTestCase
{
    /**
     * @var EndPoints
     */
    private $endPoints;

    protected function setUp()
    {
        parent::setUp();

        $this->endPoints = new EndPoints($this->provider());
    }

    /**
     *
     */
    public function test_get_not_implemented()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The endpoint "not_implemented" is not implemented');

        $this->endPoints->get('not_implemented');
    }

    /**
     *
     */
    public function test_get_success()
    {
        $endpoint = new TokenEndPoint($this->createMock(Client::class));

        $this->endPoints->add($endpoint);
        $this->assertSame($endpoint, $this->endPoints->get('token'));
    }

    /**
     *
     */
    public function test_get_with_extensions()
    {
        $client = $this->provider()->client((new ClientConfig('test')));
        $endpoint = new AuthorizationEndPoint($client);

        $this->endPoints->add($endpoint);
        $client->register($extension = new Pkce());
        $this->endPoints->register($extension);

        $return = $this->endPoints->get('authorization');

        $this->assertNotSame($endpoint, $return);
        $this->assertNotEmpty($return->get('code_challenge'));
    }

    /**
     *
     */
    public function test_uri()
    {
        $endPoint = $this->createMock(EndPointInterface::class);
        $endPoint->expects($this->any())->method('name')->willReturn('token');
        $endPoint->expects($this->any())->method('parameters')->willReturn(['foo' => 'bar']);

        $this->assertEquals('http://op.example.com/token?foo=bar', $this->endPoints->uri($endPoint));
    }

    /**
     *
     */
    public function test_request_GET()
    {
        $endPoint = $this->createMock(EndPointInterface::class);
        $endPoint->expects($this->any())->method('name')->willReturn('token');
        $endPoint->expects($this->any())->method('parameters')->willReturn(['foo' => 'bar']);

        $request = $this->endPoints->request('GET', $endPoint);

        $this->assertEquals('http://op.example.com/token?foo=bar', $request->getUri());
        $this->assertEquals('GET', $request->getMethod());
    }

    /**
     *
     */
    public function test_request_POST()
    {
        $endPoint = $this->createMock(EndPointInterface::class);
        $endPoint->expects($this->any())->method('name')->willReturn('token');
        $endPoint->expects($this->any())->method('parameters')->willReturn(['foo' => 'bar']);

        $request = $this->endPoints->request('POST', $endPoint);

        $this->assertEquals('http://op.example.com/token', $request->getUri());
        $this->assertEquals('foo=bar', $request->getBody());
        $this->assertEquals('POST', $request->getMethod());
    }

    /**
     *
     */
    public function test_authorization()
    {
        $client = $this->provider()->client((new ClientConfig('test')));
        $endpoint = new AuthorizationEndPoint($client);

        $this->endPoints->add($endpoint);

        $this->assertSame($endpoint, $this->endPoints->authorization());
    }

    /**
     *
     */
    public function test_token()
    {
        $client = $this->provider()->client((new ClientConfig('test')));
        $endpoint = new TokenEndPoint($client);

        $this->endPoints->add($endpoint);

        $this->assertSame($endpoint, $this->endPoints->token());
    }

    /**
     *
     */
    public function test_revocation()
    {
        $client = $this->provider()->client((new ClientConfig('test')));
        $endpoint = new RevocationEndPoint($client);

        $this->endPoints->add($endpoint);

        $this->assertSame($endpoint, $this->endPoints->revocation());
    }

    /**
     *
     */
    public function test_introspection()
    {
        $client = $this->provider()->client((new ClientConfig('test')));
        $endpoint = new IntrospectionEndPoint($client);

        $this->endPoints->add($endpoint);

        $this->assertSame($endpoint, $this->endPoints->introspection());
    }

    /**
     *
     */
    public function test_userinfo()
    {
        $client = $this->provider()->client((new ClientConfig('test')));
        $endpoint = new UserinfoEndPoint($client);

        $this->endPoints->add($endpoint);

        $this->assertSame($endpoint, $this->endPoints->userinfo());
    }
}
