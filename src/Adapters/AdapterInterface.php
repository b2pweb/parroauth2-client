<?php

namespace Parroauth2\Client\Adapters;

use Parroauth2\Client\Request;
use Parroauth2\Client\Response;

/**
 * Interface AdapterInterface
 *
 * @package Parroauth2\Client\Adapters
 */
interface AdapterInterface
{
    /**
     * @param Request $request
     *
     * @return Response
     */
    public function token(Request $request);

    /**
     * @param Request $request
     *
     * @return Response
     */
    public function introspect(Request $request);

    /**
     * @param Request $request
     *
     * @return Response
     */
    public function revoke(Request $request);
}