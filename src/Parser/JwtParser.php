<?php

namespace Parroauth2\Client\Parser;

use Exception;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token;
use Parroauth2\Client\Exception\ParsingException;

/**
 * Class JwtParser
 * 
 * @package Parroauth2\Client\Parser
 */
class JwtParser implements ParserInterface
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
     * @param Parser $parser
     */
    public function setParser($parser)
    {
        $this->parser = $parser;
    }

    /**
     * @return Parser
     */
    public function getParser()
    {
        return $this->parser;
    }

    /**
     * @param string $publicKey
     */
    public function setPublicKey($publicKey)
    {
        $this->publicKey = $publicKey;
    }

    /**
     * @return string
     */
    public function getPublicKey()
    {
        return $this->publicKey;
    }

    /**
     * {@inheritdoc}
     */
    public function parse($token)
    {
        $token = $this->parser()->parse($token);

        return $this
            ->verify($token)
            ->metadata($token)
        ;
    }

    /**
     * @return Parser
     */
    protected function parser()
    {
        if (!$this->parser) {
            $this->parser = new Parser();
        }

        return $this->parser;
    }

    /**
     * @param Token $token
     *
     * @return $this
     *
     * @throws ParsingException
     */
    protected function verify($token)
    {
        if ($this->publicKey) {
            try {
                $token->verify(new Sha256(), $this->publicKey);

            } catch (Exception $e) {
                throw new ParsingException('Token verification failed', 0, $e);
            }
        }

        return $this;
    }

    /**
     * @param Token $token
     *
     * @return mixed
     *
     * @throws ParsingException
     */
    protected function metadata($token)
    {
        try {
            return $token->getClaim('metadata');

        } catch (Exception $e) {
            throw new ParsingException('Token verification failed', 0, $e);
        }
    }
}