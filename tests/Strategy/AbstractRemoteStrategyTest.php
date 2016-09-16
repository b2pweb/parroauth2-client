<?php

namespace Parroauth2\Client\Tests\Strategy\Authorization;

use Bdf\PHPUnit\TestCase;
use DateTime;
use Kangaroo\Client;
use Kangaroo\Response;
use Parroauth2\Client\Exception\InternalErrorException;
use Parroauth2\Client\Grant;
use Parroauth2\Client\Strategy\Authorization\RemoteAuthorizationStrategy;
use Parroauth2\Client\Tests\Stubs\TestableHttpClientAdapter;
use ReflectionClass;

/**
 * Class AbstractRemoteStrategyTest
 *
 * @package Parroauth2\Client\Strategy\Authorization
 *
 * @group Parroauth2
 * @group Parroauth2/Client
 * @group Parroauth2/Client/Strategy
 * @group Parroauth2/Client/Strategy/Authorization
 * @group Parroauth2/Client/Strategy/Authorization/AbstractRemoteStrategyTest
 */
class AbstractRemoteStrategyTest extends TestCase
{
    /**
     * @var RemoteAuthorizationStrategy
     */
    protected $strategy;

    /**
     *
     */
    public function setUp()
    {
        $this->strategy = new RemoteAuthorizationStrategy(
            new Client('http://localhost', new TestableHttpClientAdapter()),
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
    public function test_internalError_generates_exception_from_valid_minimal_rfc_error()
    {
        $response = (new Response())
            ->setStatusCode(400)
            ->setBody((object)['error' => 'invalid_request'])
        ;

        $messageData = [
            'Configuration error',
            'Status code: ' . $response->getStatusCode(),
            'Error: ' . $response->getBody()->error,
        ];

        $expectedException = new InternalErrorException(implode(PHP_EOL, $messageData), 500);

        $class = new ReflectionClass('Parroauth2\Client\Strategy\Authorization\RemoteAuthorizationStrategy');
        $method = $class->getMethod('internalError');
        $method->setAccessible(true);

        $this->assertEquals($expectedException, $method->invokeArgs($this->strategy, [$response]));
    }

    /**
     *
     */
    public function test_internalError_generates_exception_from_valid_rfc_error()
    {
        $response = (new Response())
            ->setStatusCode(400)
            ->setBody((object)[
                'error' => 'invalid_request',
                'error_description' => 'Unable to find token or client not authenticated.',
                'error_uri' => 'http://localhost/error',
            ])
        ;

        $messageData = [
            'Configuration error',
            'Status code: ' . $response->getStatusCode(),
            'Error: ' . $response->getBody()->error,
            'Error description: ' . $response->getBody()->error_description,
            'Error URI: ' . $response->getBody()->error_uri,
        ];

        $expectedException = new InternalErrorException(implode(PHP_EOL, $messageData), 500);

        $class = new ReflectionClass('Parroauth2\Client\Strategy\Authorization\RemoteAuthorizationStrategy');
        $method = $class->getMethod('internalError');
        $method->setAccessible(true);

        $this->assertEquals($expectedException, $method->invokeArgs($this->strategy, [$response]));
    }

    /**
     *
     */
    public function test_internalError_generates_exception_from_body_as_string()
    {
        $response = (new Response())
            ->setStatusCode(404)
            ->setBody('Page not found')
        ;

        $messageData = [
            'Configuration error',
            'Status code: ' . $response->getStatusCode(),
            'Error: ' . $response->getBody(),
        ];

        $expectedException = new InternalErrorException(implode(PHP_EOL, $messageData), 500);

        $class = new ReflectionClass('Parroauth2\Client\Strategy\Authorization\RemoteAuthorizationStrategy');
        $method = $class->getMethod('internalError');
        $method->setAccessible(true);

        $this->assertEquals($expectedException, $method->invokeArgs($this->strategy, [$response]));
    }
}