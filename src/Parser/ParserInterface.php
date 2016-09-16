<?php

namespace Parroauth2\Client\Parser;

/**
 * Interface ParserInterface
 *
 * @package Parroauth2\Client\Parser
 */
interface ParserInterface
{
    /**
     * @param $token
     *
     * @return mixed
     */
    public function parse($token);
}