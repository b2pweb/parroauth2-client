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
     * Get the oauth2 uri for authorization code
     *
     * @param Request $request
     *
     * @return string
     */
    public function getAuthorizationUri(Request $request);

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

    /**
     * Gets the user info
     *
     * @param Request $request
     *
     * @return Response
     */
    public function userinfo(Request $request);
}