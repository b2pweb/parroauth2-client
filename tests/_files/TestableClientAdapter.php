<?php

namespace Kangaroo\ClientAdapter;

use Kangaroo\Request;
use Kangaroo\Response;

/**
 * Class TestableClientAdapter
 *
 * @package Kangaroo\ClientAdapter
 */
class TestableClientAdapter implements ClientAdapterInterface
{
    /**
     * @var Response
     */
    protected $response;

    /**
     * TestableClientAdapter constructor.
     */
    public function __construct()
    {
        $this->response = (new Response())->setStatusCode(200);
    }

    /**
     * @param Response $response
     *
     * @return $this
     */
    public function setResponse(Response $response)
    {
        $this->response = $response;

        return $this;
    }

    /**
     * @param Request $request
     *
     * @return Response
     */
    public function send(Request $request)
    {
        return $this->response;
    }
}