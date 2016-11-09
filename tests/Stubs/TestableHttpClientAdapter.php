<?php

namespace Parroauth2\Client\Tests\Stubs;

use Kangaroo\ClientAdapter\ClientAdapterInterface;
use Kangaroo\Request;
use Kangaroo\Response;

/**
 * Class TestableHttpClientAdapter
 */
class TestableHttpClientAdapter implements ClientAdapterInterface
{
    /**
     * @var callable|Response
     */
    protected $response;

    /**
     * {@inheritdoc}
     */
    public function send(Request $request)
    {
        if (is_callable($this->response)) {
            return call_user_func($this->response, $request);
        }

        if ($this->response) {
            return $this->response;
        }

        return (new Response())->setStatusCode(200);
    }

    /**
     * @param callable|Response $response
     */
    public function setResponse($response)
    {
        $this->response = $response;
    }
}
