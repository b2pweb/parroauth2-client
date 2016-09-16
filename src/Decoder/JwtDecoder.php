<?php

namespace Parroauth2\Client\Decoder;

use Exception;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token;
use Parroauth2\Client\Exception\ParsingException;

/**
 * Class JwtDecoder
 * 
 * @package Parroauth2\Client\Parser
 */
class JwtDecoder implements DecoderInterface
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
     * JwtDecoder constructor.
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
    public function decode($token)
    {
        try {
            $token = $this->parser->parse($token);

        } catch (Exception $e) {
            throw new ParsingException('Unable to decode token', 0, $e);
        }

        $this->verify($token);

        return [
            'active'   => $token->getClaim('active', false),
            'scope'    => $token->getClaim('scope', ''),
            'metadata' => $token->getClaim('metadata', []),
            'exp'      => $token->getClaim('exp', 0),
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