<?php

namespace Parroauth2\Client\ClientAdapters;

use Parroauth2\Client\Request;
use Parroauth2\Client\Response;

/**
 * ClientAdapterInterface
 */
interface ClientAdapterInterface
{
    /**
     * Request a oauth2 token
     *
     * @param Request $request
     *
     * @return Response
     */
    public function token(Request $request);

    /**
     * Request a oauth2 authorization code
     *
     * @param Request $request
     * @param callable $onSuccess
     *
     * @return Response
     */
    public function authorize(Request $request, callable $onSuccess = null);

    /**
     * Introspect a token
     *
     * @param Request $request
     *
     * @return Response
     */
    public function introspect(Request $request);

    /**
     * Revoke a token
     *
     * @param Request $request
     *
     * @return Response
     */
    public function revoke(Request $request);
}