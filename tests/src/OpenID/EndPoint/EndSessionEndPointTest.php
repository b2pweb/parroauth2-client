<?php

namespace Parroauth2\Client\OpenID\EndPoint;

use Parroauth2\Client\ClientConfig;
use Parroauth2\Client\EndPoint\EndPointTransformerInterface;
use Parroauth2\Client\Tests\UnitTestCase;

/**
 * Class EndSessionEndPointTest
 */
class EndSessionEndPointTest extends UnitTestCase
{
    /**
     * @var EndSessionEndPoint
     */
    private $endPoint;

    private $clonedEndPoint;

    protected function setUp(): void
    {
        parent::setUp();

        $this->endPoint = new EndSessionEndPoint($this->provider()->client((new ClientConfig('test'))));
        $this->clonedEndPoint = clone $this->endPoint;
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        $this->assertEquals($this->clonedEndPoint, $this->endPoint);
    }

    /**
     *
     */
    public function test_name()
    {
        $this->assertEquals('end_session', $this->endPoint->name());
    }

    /**
     *
     */
    public function test_parameters()
    {
        $this->assertEmpty($this->endPoint->parameters());

        $endPoint = $this->endPoint->set('foo', 'bar');
        $this->assertNotSame($endPoint, $this->endPoint);
        $this->assertArrayNotHasKey('foo', $this->endPoint->parameters());
        $this->assertEquals('bar', $endPoint->get('foo'));
        $this->assertEquals(['foo' => 'bar'], $endPoint->parameters());
        $this->assertEquals('http://op.example.com/logout?foo=bar', $endPoint->uri());
    }

    /**
     *
     */
    public function test_apply()
    {
        $ret = $this->createMock(EndSessionEndPoint::class);
        $transformer = $this->createMock(EndPointTransformerInterface::class);
        $transformer->expects($this->once())->method('onEndSession')->with($this->endPoint)->willReturn($ret);

        $this->assertSame($ret, $this->endPoint->apply($transformer));
    }

    /**
     *
     */
    public function test_idToken()
    {
        $this->assertEquals('http://op.example.com/logout?id_token_hint=my_id_token', $this->endPoint->idToken('my_id_token')->uri());
    }

    /**
     *
     */
    public function test_redirectUri()
    {
        $this->assertEquals('http://op.example.com/logout?post_logout_redirect_uri=http%3A%2F%2Frp.example.com%2Flogout_success', $this->endPoint->redirectUri('http://rp.example.com/logout_success')->uri());
        $this->assertEquals('http://op.example.com/logout?post_logout_redirect_uri=http%3A%2F%2Frp.example.com%2Flogout_success&state=csrf', $this->endPoint->redirectUri('http://rp.example.com/logout_success', 'csrf')->uri());
    }
}
