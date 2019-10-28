<?php

namespace Parroauth2\Client\EndPoint\Introspection;

/**
 * Response of the introspection endpoint
 *
 * @see https://tools.ietf.org/html/rfc7662#section-2.2
 */
class IntrospectionResponse
{
    /**
     * @var array
     */
    private $data;


    /**
     * IntrospectionResponse constructor.
     *
     * @param array $data
     */
    public function __construct(array $data)
    {
        $this->data = $data;
    }

    /**
     * @return boolean
     */
    public function active(): bool
    {
        return $this->data['active'];
    }

    /**
     * @return string[]
     */
    public function scopes(): ?array
    {
        return isset($this->data['scope']) ? explode(' ', $this->data['scope']) : null;
    }

    /**
     * @return string
     */
    public function clientId(): ?string
    {
        return $this->data['client_id'] ?? null;
    }

    /**
     * @return string
     */
    public function username(): ?string
    {
        return $this->data['username'] ?? null;
    }

    /**
     * @return string
     */
    public function tokenType(): ?string
    {
        return $this->data['token_type'] ?? null;
    }

    /**
     * @return int
     */
    public function expireAt(): ?int
    {
        return $this->data['exp'] ?? null;
    }

    /**
     * @return int
     */
    public function issuedAt(): ?int
    {
        return $this->data['iat'] ?? null;
    }

    /**
     * @return int
     */
    public function notBefore(): ?int
    {
        return $this->data['nbf'] ?? null;
    }

    /**
     * @return string
     */
    public function subject(): ?string
    {
        return $this->data['sub'] ?? null;
    }

    /**
     * @return string|string[]|null
     */
    public function audience()
    {
        return $this->data['aud'] ?? null;
    }

    /**
     * @return string
     */
    public function issuer(): ?string
    {
        return $this->data['iss'] ?? null;
    }

    /**
     * @return string
     */
    public function jwtId(): ?string
    {
        return $this->data['jti'] ?? null;
    }

    /**
     * Get all claims of the introspection
     *
     * @return array
     */
    public function claims(): array
    {
        return $this->data;
    }
}
