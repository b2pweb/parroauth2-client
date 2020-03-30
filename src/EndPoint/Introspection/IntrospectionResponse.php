<?php

namespace Parroauth2\Client\EndPoint\Introspection;

use Parroauth2\Client\Claim\Claims;

/**
 * Response of the introspection endpoint
 *
 * @see https://tools.ietf.org/html/rfc7662#section-2.2
 */
class IntrospectionResponse extends Claims
{
    /**
     * @return boolean
     */
    public function active(): bool
    {
        return $this['active'];
    }

    /**
     * @return string[]
     */
    public function scopes(): ?array
    {
        return isset($this['scope']) ? explode(' ', $this['scope']) : null;
    }

    /**
     * @return string
     */
    public function clientId(): ?string
    {
        return $this->claim('client_id');
    }

    /**
     * @return string
     */
    public function username(): ?string
    {
        return $this->claim('username');
    }

    /**
     * @return string
     */
    public function tokenType(): ?string
    {
        return $this->claim('token_type');
    }

    /**
     * @return int
     */
    public function expireAt(): ?int
    {
        return $this->claim('exp');
    }

    /**
     * @return int
     */
    public function issuedAt(): ?int
    {
        return $this->claim('iat');
    }

    /**
     * @return int
     */
    public function notBefore(): ?int
    {
        return $this->claim('nbf');
    }

    /**
     * @return string
     */
    public function subject(): ?string
    {
        return $this->claim('sub');
    }

    /**
     * @return string|string[]|null
     */
    public function audience()
    {
        return $this->claim('aud');
    }

    /**
     * @return string
     */
    public function issuer(): ?string
    {
        return $this->claim('iss');
    }

    /**
     * @return string
     */
    public function jwtId(): ?string
    {
        return $this->claim('jti');
    }
}
