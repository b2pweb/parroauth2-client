<?php

namespace Parroauth2\Client\EndPoint\Token;

use DateTime;

/**
 * Response of the token endpoint
 *
 * @see https://tools.ietf.org/html/rfc6749#section-5.1
 *
 * @psalm-immutable
 */
class TokenResponse
{
    /**
     * @var array<string, mixed>
     */
    private $response;

    /**
     * @var DateTime|null
     */
    private $expiresAt;


    /**
     * TokenResponse constructor.
     *
     * @param array<string, mixed> $response
     */
    public function __construct(array $response)
    {
        $this->response = $response;

        if (isset($response['expires_in']) && $response['expires_in'] >= 0) {
            /** @psalm-suppress  ImpureMethodCall */
            $this->expiresAt = (new DateTime())->add(new \DateInterval('PT'.(int) $response['expires_in'].'S'));
        }
    }

    /**
     * Get the access token
     *
     * @return string
     */
    public function accessToken(): string
    {
        return $this->response['access_token'];
    }

    /**
     * Get the access token type
     * The value is in lower case
     *
     * @return string
     */
    public function type(): string
    {
        return strtolower($this->response['token_type']);
    }

    /**
     * Get the expiration date time
     * May be null if expires_in is not provided
     *
     * @return DateTime|null
     */
    public function expiresAt(): ?DateTime
    {
        return $this->expiresAt;
    }

    /**
     * Check if the access token has expired
     * If expires_in is not provided, this method will always return true
     *
     * Note: This method does not guarantee that the token is actually valid
     *
     * @return bool
     */
    public function expired(): bool
    {
        return $this->expiresAt && $this->expiresAt < new DateTime();
    }

    /**
     * Get the issued refresh token
     *
     * @return string|null
     */
    public function refreshToken(): ?string
    {
        return $this->response['refresh_token'] ?? null;
    }

    /**
     * Get the list of requested (and authorized) scopes
     *
     * @return string[]|null
     */
    public function scopes(): ?array
    {
        if (isset($this->response['scope'])) {
            return explode(' ', $this->response['scope']);
        }

        return null;
    }

    /**
     * Get a response field
     *
     * @param string $key
     * @param null $default
     *
     * @return mixed
     */
    public function get(string $key, $default = null)
    {
        return $this->response[$key] ?? $default;
    }
}
