<?php

namespace Parroauth2\Client\Decoder;

/**
 * Interface DecoderInterface
 *
 * @package Parroauth2\Client\Decoder
 */
interface DecoderInterface
{
    /**
     * @param string $token
     *
     * @return array
     */
    public function decode($token);
}