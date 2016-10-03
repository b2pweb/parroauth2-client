<?php

namespace Parroauth2\Client\Unserializer;

use Exception;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token;
use Parroauth2\Client\Exception\ParsingException;

/**
 * Class JwtUnserializer
 * 
 * @package Parroauth2\Client\Parser
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

        } catch (Exception $e) {
            throw new ParsingException('Unable to unserialize token', 0, $e);
        }

        $this->verify($token);

        return [
            'scope'      => $token->getClaim('scope', ''),
            'client_id'  => $token->getClaim('aud', ''),
            'username'   => $token->getClaim('username', ''),
            'token_type' => $token->getClaim('token_type', ''),
            'exp'        => $token->getClaim('exp'),
            'iat'        => $token->getClaim('iat'),
            'nbf'        => $token->getClaim('nbf'),
            'sub'        => $token->getClaim('sub', ''),
            'aud'        => $token->getClaim('aud', ''),
            'iss'        => $token->getClaim('iss', ''),
            'jti'        => $token->getClaim('jti', ''),
            'metadata'   => $token->getClaim('metadata', []),
        ];
    }

    /**
     * @param Token $token
     *
     * @throws ParsingException
     */
    protected function verify($token)
    {
        if (!$this->publicKey) {
            return;
        }

        try {
            $token->verify(new Sha256(), $this->publicKey);

        } catch (Exception $e) {
            throw new ParsingException('Unable to verify token', 0, $e);
        }
    }
}