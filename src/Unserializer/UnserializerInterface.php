<?php

namespace Parroauth2\Client\Unserializer;

/**
 * Interface UnserializerInterface
 *
 * @package Parroauth2\Client\Unserializer
 */
interface UnserializerInterface
{
    /**
     * @param string $token
     *
     * @return array
     */
    public function unserialize($token);
}