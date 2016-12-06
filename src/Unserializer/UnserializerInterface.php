<?php

namespace Parroauth2\Client\Unserializer;

/**
 * Interface UnserializerInterface
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