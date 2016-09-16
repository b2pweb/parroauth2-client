<?php

namespace Parroauth2\Client\Tests;

use Bdf\PHPUnit\TestCase;
use DateTime;
use Parroauth2\Client\Introspection;
use Parroauth2\Client\IntrospectionClient;
use Parroauth2\Client\Grant;
use Parroauth2\Client\Strategy\Introspection\IntrospectionStrategyInterface;

/**
 * Class IntrospectionClientTest
 * 
 * @package Parroauth2\Client
 *
 * @group Parroauth2
 * @group Parroauth2/Client
 * @group Parroauth2/Client/IntrospectionClient
 */
class IntrospectionClientTest extends TestCase
{
    /**
     * @var IntrospectionClient
     */
    protected $client;

    /**
     * @var IntrospectionStrategyInterface
     */
    protected $strategy;

    /**
     * 
     */
    public function setUp()
    {
        $this->strategy = $this->getMock('Parroauth2\Client\Strategy\Introspection\IntrospectionStrategyInterface', ['introspect']);

        $this->client = new IntrospectionClient($this->strategy);
    }

    /**
     *
     */
    public function test_introspect_throws_connection_exception_if_no_token_is_set()
    {
        $this->setExpectedException('Parroauth2\Client\Exception\InternalErrorException', 'Unable to introspect empty token');

        $this->client->introspect('');
    }

    /**
     *
     */
    public function test_introspect_returns_the_token_introspection()
    {
        $grant = new Grant('access_token', new DateTime('tomorrow'), 'refresh_token', 'Bearer');
        $introspection = new Introspection();

        $this->strategy
            ->expects($this->once())
            ->method('introspect')
            ->with($grant->getAccess())
            ->will($this->returnValue($introspection))
        ;

        $this->assertSame($introspection, $this->client->introspect($grant));
    }
}