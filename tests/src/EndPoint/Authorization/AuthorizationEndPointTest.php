<?php

namespace Parroauth2\Client\EndPoint\Authorization;

use Parroauth2\Client\ClientConfig;
use Parroauth2\Client\EndPoint\EndPointTransformerInterface;
use Parroauth2\Client\Tests\UnitTestCase;

/**
 * Class AuthorizationEndPointTest
 */
class AuthorizationEndPointTest extends UnitTestCase
{
    /**
     * @var AuthorizationEndPoint
     */
    private $endPoint;

    private $clonedEndPoint;

    protected function setUp(): void
    {
        parent::setUp();

        $this->endPoint = new AuthorizationEndPoint($this->provider()->client((new ClientConfig('test'))));
        $this->clonedEndPoint = clone $this->endPoint;
    }

    protected function tearDown(): void
    {
        $this->assertEquals($this->clonedEndPoint, $this->endPoint);
    }

    /**
     *
     */
    public function test_name()
    {
        $this->assertEquals('authorization', $this->endPoint->name());
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
        $this->assertEquals('http://op.example.com/authorize?foo=bar', $endPoint->uri());
    }

    /**
     *
     */
    public function test_uri_with_extra_parameters()
    {
        $endPoint = $this->endPoint
            ->set('foo', 'bar')
            ->set('azerty', 'uiop')
        ;
        $this->assertEquals('http://op.example.com/authorize?foo=baz&azerty=uiop&other=aaa', $endPoint->uri(['foo' => 'baz', 'other' => 'aaa']));
        $this->assertSame(['foo' => 'bar', 'azerty' => 'uiop'], $endPoint->parameters());
    }

    /**
     *
     */
    public function test_apply()
    {
        $ret = $this->createMock(AuthorizationEndPoint::class);
        $transformer = $this->createMock(EndPointTransformerInterface::class);
        $transformer->expects($this->once())->method('onAuthorization')->with($this->endPoint)->willReturn($ret);

        $this->assertSame($ret, $this->endPoint->apply($transformer));
    }

    /**
     *
     */
    public function test_code_without_redirectUri()
    {
        $endPoint = $this->endPoint->code();

        $this->assertNotEquals($endPoint, $this->endPoint);
        $this->assertEquals('http://op.example.com/authorize?client_id=test&response_type=code&state='.$endPoint->get('state'), $endPoint->uri());
    }

    /**
     *
     */
    public function test_code_with_redirectUri()
    {
        $endPoint = $this->endPoint->code('http://client.example.com/connect');

        $this->assertNotEquals($endPoint, $this->endPoint);
        $this->assertEquals('http://op.example.com/authorize?client_id=test&response_type=code&redirect_uri=http%3A%2F%2Fclient.example.com%2Fconnect&state='.$endPoint->get('state'), $endPoint->uri());
    }

    /**
     *
     */
    public function test_code_with_scopes()
    {
        $endPoint = $this->endPoint->code(null, ['foo', 'bar']);

        $this->assertNotEquals($endPoint, $this->endPoint);
        $this->assertEquals('http://op.example.com/authorize?client_id=test&response_type=code&scope=foo+bar&state='.$endPoint->get('state'), $endPoint->uri());
    }

    /**
     *
     */
    public function test_scope()
    {
        $endPoint = $this->endPoint->scope(['foo', 'bar']);

        $this->assertNotEquals($endPoint, $this->endPoint);
        $this->assertEquals('http://op.example.com/authorize?scope=foo+bar', $endPoint->uri());
    }

    /**
     *
     */
    public function test_state_generate()
    {
        $endPoint = $this->endPoint->state();

        $this->assertNotEquals($endPoint, $this->endPoint);
        $this->assertEquals(43, strlen($endPoint->get('state')));
        $this->assertEquals('http://op.example.com/authorize?state='.$endPoint->get('state'), $endPoint->uri());

        $this->assertNotEquals($endPoint->get('state'), $this->endPoint->state()->get('state'));
    }

    /**
     *
     */
    public function test_state()
    {
        $endPoint = $this->endPoint->state('my-state');

        $this->assertNotEquals($endPoint, $this->endPoint);
        $this->assertEquals('http://op.example.com/authorize?state=my-state', $endPoint->uri());
    }
}
