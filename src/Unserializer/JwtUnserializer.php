<?php

namespace Parroauth2\Client\Unserializer;

use Exception;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token;

/**
 * JwtUnserializer
 */
class JwtUnserializer implements UnserializerInterface
{
    /**
     * @var Parser
     */
    protected $parser;

    /**
     * @var string
     */
    protected $publicKey;

    /**
     * JwtUnserializer constructor.
     *
     * @param Parser $parser
     * @param string $publicKey
     */
    public function __construct(Parser $parser = null, $publicKey = null)
    {
        $this->parser = $parser ?: new Parser();
        $this->publicKey = $publicKey;
    }

    /**
     * {@inheritdoc}
     */
    public function unserialize($token)
    {
        try {
            $token = $this->parser->parse($token);

            $this->checkSignature($token);
        } catch (Exception $e) {
            return null;
        }

        return [
            'scope'      => $token->getClaim('scope', ''),
            'client_id'  => $token->getClaim('aud', ''),
            'username'   => $token->getClaim('username', ''),
            'token_type' => $token->getClaim('token_type', ''),
            'exp'        => $token->getClaim('exp', 0),
            'iat'        => $token->getClaim('iat', 0),
            'nbf'        => $token->getClaim('nbf', 0),
            'sub'        => $token->getClaim('sub', ''),
            'aud'        => $token->getClaim('aud', ''),
            'iss'        => $token->getClaim('iss', ''),
            'jti'        => $token->getClaim('jti', ''),
            'metadata'   => $token->getClaim('metadata', []),
        ];
    }

    /**
     * Check the token signature
     *
     * @param Token $token
     */
    protected function checkSignature($token)
    {
        if ($this->publicKey !== null) {
            $token->verify(new Sha256(), $this->publicKey);
        }
    }
}