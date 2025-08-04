<?php

namespace Parroauth2\Client\OpenID\EndPoint\Token;

use DateInterval;
use Parroauth2\Client\Client;
use Parroauth2\Client\ClientInterface;
use Parroauth2\Client\EndPoint\Token\TokenEndPoint as BaseTokenEndPoint;
use Parroauth2\Client\OpenID\IdToken\IdTokenParserInterface;
use Parroauth2\Client\Util\NativeClock;
use Psr\Clock\ClockInterface;

/**
 * Token endpoint for OpenID Connect provider
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
 */
class TokenEndPoint extends BaseTokenEndPoint
{
    private readonly ClientInterface $client;
    private readonly IdTokenParserInterface $idTokenParser;
    private readonly ClockInterface $clock;

    /**
     * TokenEndPoint constructor.
     *
     * @param ClientInterface $client
     * @param IdTokenParserInterface $idTokenParser
     * @param ClockInterface|null $clock
     */
    public function __construct(ClientInterface $client, IdTokenParserInterface $idTokenParser, ?ClockInterface $clock = null)
    {
        parent::__construct($client, $this->parseResponse(...));

        $this->client = $client;
        $this->idTokenParser = $idTokenParser;
        $this->clock = $clock ?? NativeClock::instance();
    }

    /**
     * Parse the response and set the ID Token
     *
     * @param array<string, mixed> $response
     *
     * @return TokenResponse
     */
    public function parseResponse(array $response): TokenResponse
    {
        $expiresAt = null;

        if (isset($response['expires_in']) && $response['expires_in'] >= 0) {
            $expiresAt = $this->clock->now()->add(new DateInterval('PT' . (int) $response['expires_in'] . 'S'));
        }

        if (!isset($response['id_token'])) {
            return new TokenResponse($response, null, $expiresAt);
        }

        return new TokenResponse($response, $this->idTokenParser->parse($this->client, $response['id_token']), $expiresAt);
    }
}
