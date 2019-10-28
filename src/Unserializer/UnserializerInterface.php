<?php

namespace Parroauth2\Client\Unserializer;

use Lcobucci\JWT\Token;

/**
 * UnserializerInterface
 *
 * @deprecated Use JwtDecoder
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
