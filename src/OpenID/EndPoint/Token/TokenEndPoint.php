<?php

namespace Parroauth2\Client\OpenID\EndPoint\Token;

use Parroauth2\Client\Client;
use Parroauth2\Client\ClientInterface;
use Parroauth2\Client\EndPoint\Token\TokenEndPoint as BaseTokenEndPoint;
use Parroauth2\Client\OpenID\IdToken\IdTokenParserInterface;

/**
 * Token endpoint for OpenID Connect provider
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
 */
class TokenEndPoint extends BaseTokenEndPoint
{
    /**
     * @var ClientInterface
     */
    private $client;

    /**
     * @var IdTokenParserInterface
     */
    private $idTokenParser;


    /**
     * TokenEndPoint constructor.
     *
     * @param ClientInterface $client
     * @param IdTokenParserInterface $idTokenParser
     */
    public function __construct(ClientInterface $client, IdTokenParserInterface $idTokenParser)
    {
        parent::__construct($client, [$this, 'parseResponse']);

        $this->client = $client;
        $this->idTokenParser = $idTokenParser;
    }

    /**
     * Parse the response and set the ID Token
     *
     * @param array $response
     *
     * @return TokenResponse
     */
    public function parseResponse(array $response): TokenResponse
    {
        if (!isset($response['id_token'])) {
            return new TokenResponse($response, null);
        }

        return new TokenResponse($response, $this->idTokenParser->parse($this->client, $response['id_token']));
    }
}
