<?php

namespace Parroauth2\Client\Tests\Strategy\Introspection;

use Bdf\PHPUnit\TestCase;
use Kangaroo\Client;
use Kangaroo\Response;
use Parroauth2\Client\Introspection;
use Parroauth2\Client\Strategy\Introspection\RemoteIntrospectionStrategy;
use Parroauth2\Client\Tests\Stubs\TestableHttpClientAdapter;

/**
 * Class RemoteIntrospectionStrategyTest
 * 
 * @package Parroauth2\Client\Strategy\Introspection
 * 
 * @group Parroauth2
 * @group Parroauth2/Client
 * @group Parroauth2/Client/Strategy
 * @group Parroauth2/Client/Strategy/Introspection
 * @group Parroauth2/Client/Strategy/Introspection/RemoteIntrospectionStrategy
 */
class RemoteIntrospectionStrategyTest extends TestCase
{
    /**
     * @var RemoteIntrospectionStrategy
     */
    protected $strategy;

    /**
     * @var TestableHttpClientAdapter
     */
    protected $adapter;

    /**
     *
     */
    public function setUp()
    {
        $this->adapter = new TestableHttpClientAdapter();

        $this->strategy = new RemoteIntrospectionStrategy(
            new Client('http://localhost', $this->adapter),
            [
                'path'         => '/oauth',
                'clientId'     => 'clientId',
                'clientSecret' => 'clientSecret',
            ]
        );
    }

    /**
     *
     */
    public function test_introspect_throws_internal_exception_if_an_error_occurs()
    {
        $this->setExpectedException('Parroauth2\Client\Exception\InternalErrorException');

        $this->adapter->setResponse((new Response())->setStatusCode(401));

        $this->strategy->introspect('access_token');
    }

    /**
     *
     */
    public function test_introspect_returns_data_properly()
    {
        $scopes = ['scope1', 'scope2'];
        $metadata = [
            'id' => 123,
            'name' => 'Phpunit',
        ];

        $this->adapter->setResponse(
            (new Response())
                ->setStatusCode(200)
                ->setBody((object)[
                    'active' => true,
                    'scope' => implode(' ', $scopes),
                    'metadata' => $metadata,
                ])
        );

        $introspection = (new Introspection())
            ->setActive(true)
            ->setScopes($scopes)
            ->setMetadata($metadata)
        ;

        $this->assertEquals($introspection, $this->strategy->introspect('access_token'));
    }
}