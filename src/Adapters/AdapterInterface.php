<?php

namespace Parroauth2\Client\Adapters;

use Parroauth2\Client\Request;
use Parroauth2\Client\Response;

/**
 * Interface AdapterInterface
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
     * @param callable $onSuccess
     *
     * @return Response
     */
    public function authorize(Request $request, callable $onSuccess = null);

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