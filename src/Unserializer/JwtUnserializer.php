<?php

namespace Parroauth2\Client\Unserializer;

use Exception;

/**
 * JwtUnserializer
 */
class JwtUnserializer implements UnserializerInterface
{
    /**
     * @var string
     */
    protected $publicKey;

    /**
     * JwtUnserializer constructor.
     *
     * @param string $publicKey
     */
    public function __construct($publicKey = null)
    {
        $this->publicKey = $publicKey;
    }

    /**
     * {@inheritdoc}
     */
    public function unserialize($token)
    {
        try {
            $token = \JWT::decode($token, $this->publicKey, array_keys(\JWT::$supported_algs));
        } catch (Exception $e) {
            return null;
        }

        return [
            'scope'      => $token->scope ?? '',
            'client_id'  => $token->aud ?? '',
            'username'   => $token->username ?? '',
            'token_type' => $token->token_type ?? '',
            'exp'        => $token->exp ?? 0,
            'iat'        => $token->iat ?? 0,
            'nbf'        => $token->nbf ?? 0,
            'sub'        => $token->sub ?? '',
            'aud'        => $token->aud ?? '',
            'iss'        => $token->iss ?? '',
            'jti'        => $token->jti ?? '',
            'metadata'   => $token->metadata ?? [],
        ];
    }
}
