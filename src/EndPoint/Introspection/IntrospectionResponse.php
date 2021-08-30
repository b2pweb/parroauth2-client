<?php

namespace Parroauth2\Client\EndPoint\Introspection;

use Parroauth2\Client\Claim\Claims;

/**
 * Response of the introspection endpoint
 *
 * @see https://tools.ietf.org/html/rfc7662#section-2.2
 *
 * @psalm-immutable
 */
class IntrospectionResponse extends Claims
{
    /**
     * Does the current token is active ?
     *
     * If this value is false, the token should be considered as expired, and cannot be used,
     * and also all other claims may be null
     *
     * @return boolean
     */
    public function active(): bool
    {
        return $this['active'];
    }

    /**
     * Get the list of scope names
     *
     * @return list<string>|null
     */
    public function scopes(): ?array
    {
        return isset($this['scope']) ? explode(' ', $this['scope']) : null;
    }

    /**
     * Get the requested client id
     *
     * @return string|null
     */
    public function clientId(): ?string
    {
        return $this->claim('client_id');
    }

    /**
     * Resource owner username
     *
     * @return string|null
     */
    public function username(): ?string
    {
        return $this->claim('username');
    }

    /**
     * Type of the token
     * Available values are "bearer" and "mac"
     *
     * @return string|null
     */
    public function tokenType(): ?string
    {
        return $this->claim('token_type');
    }

    /**
     * Unix timestamp indicating the token expiration date
     *
     * @return int|null
     */
    public function expireAt(): ?int
    {
        return $this->claim('exp');
    }

    /**
     * Unix timestamp indicating the token creation date
     *
     * @return int|null
     */
    public function issuedAt(): ?int
    {
        return $this->claim('iat');
    }

    /**
     * Unix timestamp indicating when the token can be used
     *
     * @return int|null
     */
    public function notBefore(): ?int
    {
        return $this->claim('nbf');
    }

    /**
     * Subject of the token
     * Usually identify the resource owner, like a user id
     *
     * @return string|null
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
     * The token issuer (i.e. oauth authority)
     * This value is usually an URI
     *
     * @return string|null
     */
    public function issuer(): ?string
    {
        return $this->claim('iss');
    }

    /**
     * Unique identifier of the JWT
     *
     * @return string|null
     */
    public function jwtId(): ?string
    {
        return $this->claim('jti');
    }
}
