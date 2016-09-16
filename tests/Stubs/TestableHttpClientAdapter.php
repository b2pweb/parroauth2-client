<?php

namespace Parroauth2\Client\Tests\Stubs;

use Kangaroo\ClientAdapter\ClientAdapterInterface;
use Kangaroo\Request;
use Kangaroo\Response;

/**
 * Class TestableHttpClientAdapter
 *
 * @package Parroauth2\Client\Tests\Stubs
 */
class TestableHttpClientAdapter implements ClientAdapterInterface
{
    /**
     * @var Response
     */
    protected $response;

    /**
     * TestableHttpClientAdapter constructor.
     */
    public function __construct()
    {
        $this->response = (new Response())->setStatusCode(200);
    }

    /**
     * {@inheritdoc}
     */
    public function send(Request $request)
    {
        return $this->response;
    }

    /**
     * @param Response $response
     */
    public function setResponse($response)
    {
        $this->response = $response;
    }
}
