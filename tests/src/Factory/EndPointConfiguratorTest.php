<?php

namespace Parroauth2\Client\Factory;

use Parroauth2\Client\ClientConfig;
use Parroauth2\Client\EndPoint\EndPointInterface;
use Parroauth2\Client\EndPoint\EndPointParametersTrait;
use Parroauth2\Client\EndPoint\EndPointTransformerInterface;
use Parroauth2\Client\Tests\UnitTestCase;

/**
 * Class EndPointConfiguratorTest
 */
class EndPointConfiguratorTest extends UnitTestCase
{
    /**
     *
     */
    public function test_configure_success()
    {
        $called = false;
        $endpoint = $this->createMock(EndPointInterface::class);
        $endpoint->expects($this->any())->method('name')->willReturn('endpoint');

        $configurator = new EndPointConfigurator([
            'endpoint' => function () use(&$called, $endpoint) {
                $called = true;
                return $endpoint;
            }
        ]);

        $client = $this->provider(['endpoint_endpoint' => ''])->client(new ClientConfig('test'));
        $configurator->configure($client);

        $this->assertTrue($called);
        $this->assertSame($endpoint, $client->endPoints()->get('endpoint'));
    }

    /**
     *
     */
    public function test_configure_with_class_name()
    {
        $configurator = new EndPointConfigurator([
            'my' => MyEndPoint::class,
        ]);

        $client = $this->provider(['my_endpoint' => ''])->client(new ClientConfig('test'));
        $configurator->configure($client);

        $this->assertInstanceOf(MyEndPoint::class, $client->endPoints()->get('my'));
    }

    /**
     *
     */
    public function test_configure_not_supported_by_provider()
    {
        $called = false;
        $configurator = new EndPointConfigurator([
            'endpoint' => function () use(&$called) {
                $called = true;
                return $this->createMock(EndPointInterface::class);
            }
        ]);

        $client = $this->provider()->client(new ClientConfig('test'));
        $configurator->configure($client);

        $this->assertFalse($called);
    }
}

class MyEndPoint implements EndPointInterface
{
    use EndPointParametersTrait;

    public function name(): string { return 'my'; }
    public function apply(EndPointTransformerInterface $transformer) { }
}
