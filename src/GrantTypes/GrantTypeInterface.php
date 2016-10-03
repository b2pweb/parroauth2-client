<?php

namespace Parroauth2\Client\GrantTypes;

use Parroauth2\Client\Request;

/**
 * Interface GrantTypeInterface
 *
 * @package Parroauth2\Client\GrantTypes
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