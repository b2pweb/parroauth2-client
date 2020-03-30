<?php

namespace Parroauth2\Client\OpenID\IdToken;

use Parroauth2\Client\Claim\Claims;

/**
 * Store the ID Token claims
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#IDToken
 */
final class IdToken extends Claims
{
    /**
     * @var string
     */
    private $raw;

    /**
     * @var array
     */
    private $headers;

    /**
     * IdToken constructor.
     *
     * @param string $raw
     * @param array $claims
     * @param array $headers
     */
    public function __construct(string $raw, array $claims, array $headers)
    {
        parent::__construct($claims);

        $this->raw = $raw;
        $this->headers = $headers;
    }

    /**
     * Get the ID Token issuer (i.e. base URL of the provider)
     *
     * @return string
     */
    public function issuer(): string
    {
        return $this['iss'];
    }

    /**
     * Audience of the ID Token
     * Must contains the client id
     *
     * @return string|string[]
     */
    public function audience()
    {
        return $this['aud'];
    }

    /**
     * Get the access token hash (at_hash), if provided
     *
     * @return string|null
     */
    public function accessTokenHash(): ?string
    {
        return $this->claim('at_hash');
    }

    /**
     * Get the authorized party (azp), if provided
     *
     * @return string|null
     */
    public function authorizedParty(): ?string
    {
        return $this->claim('azp');
    }

    /**
     * Get the time when the ID Token is issued
     * The time is an UNIX timestamp
     *
     * @return int
     */
    public function issuedAt(): int
    {
        return $this['iat'];
    }

    /**
     * The nonce, provided on the authorization endpoint
     *
     * @return string
     */
    public function nonce(): string
    {
        return $this->claim('nonce', '');
    }

    /**
     * The session id
     *
     * @return string|null
     */
    public function sid(): ?string
    {
        return $this->claim('nonce');
    }

    /**
     * Get the raw value of the ID Token
     *
     * @return string
     */
    public function raw(): string
    {
        return $this->raw;
    }

    /**
     * Get the ID Token JOSE headers
     *
     * @return array
     */
    public function headers(): array
    {
        return $this->headers;
    }

    /**
     * Get a JOSE header value
     *
     * @param string $name The header name
     * @param mixed $default Default value to return when the header cannot be found
     *
     * @return mixed
     */
    public function header(string $name, $default = null)
    {
        return $this->headers[$name] ?? $default;
    }

    /**
     * Get the string representation of the ID Token
     *
     * @return string
     */
    public function __toString(): string
    {
        return $this->raw;
    }
}
