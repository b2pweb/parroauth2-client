<?php

namespace Parroauth2\Client\Unserializer;

/**
 * UnserializerInterface
 */
interface UnserializerInterface
{
    /**
     * Unserialize a token
     *
     * @param string $token
     *
     * @return null|array
     */
    public function unserialize($token);
}