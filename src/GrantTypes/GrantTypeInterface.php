<?php

namespace Parroauth2\Client\GrantTypes;

use Parroauth2\Client\Request;

/**
 * Interface GrantTypeInterface
 */
interface GrantTypeInterface
{
    /**
     * @param Request $request
     *
     * @return $this
     */
    public function acquaint(Request $request);
}