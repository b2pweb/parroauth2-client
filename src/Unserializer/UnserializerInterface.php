<?php

namespace Parroauth2\Client\Unserializer;

use Lcobucci\JWT\Token;

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
     * @return null|Token
     */
    public function unserialize($token);
}