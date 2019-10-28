<?php

namespace Parroauth2\Client\Unserializer;

use Exception;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token;

/**
 * JwtUnserializer
 *
 * @deprecated Use JwtDecoder
 */
class JwtUnserializer implements UnserializerInterface
{
    /**
     * @var Parser
     */
    private $parser;

    /**
     * @var Signer
     */
    private $signer;

    /**
     * @var string
     */
    private $publicKey;

    /**
     * JwtUnserializer constructor.
     *
     * @param null|string $publicKey
     * @param null|Signer $signer
     * @param null|Parser $parser
     */
    public function __construct(string $publicKey = null, Signer $signer = null, Parser $parser = null)
    {
        $this->publicKey = $publicKey;
        $this->signer = $signer;
        $this->parser = $parser ?: new Parser();
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

        return $token;
    }

    /**
     * Check the token signature
     *
     * @param Token $token
     */
    protected function checkSignature($token)
    {
        if ($this->publicKey !== null) {
            if (!$token->verify($this->signer ?: new Sha256(), $this->publicKey)) {
                throw new \InvalidArgumentException('Invalid signature');
            }
        }
    }
}
