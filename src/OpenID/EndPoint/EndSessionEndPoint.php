<?php

namespace Parroauth2\Client\OpenID\EndPoint;

use Parroauth2\Client\ClientInterface;
use Parroauth2\Client\EndPoint\EndPointInterface;
use Parroauth2\Client\EndPoint\EndPointParametersTrait;
use Parroauth2\Client\EndPoint\EndPointTransformerInterface;
use Parroauth2\Client\Exception\UnsupportedServerOperation;
use Parroauth2\Client\OpenID\IdToken\IdToken;

/**
 * Endpoint for notify the OP that the user has logged out
 * This endpoint must be called by the user agent using a redirection
 *
 * @see https://openid.net/specs/openid-connect-session-1_0.html#RPLogout
 */
class EndSessionEndPoint implements EndPointInterface
{
    use EndPointParametersTrait;

    const NAME = 'end_session';

    /**
     * @var ClientInterface
     */
    private $client;

    /**
     * EndSessionEndPoint constructor.
     *
     * @param ClientInterface $client
     */
    public function __construct(ClientInterface $client)
    {
        $this->client = $client;
    }

    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return self::NAME;
    }

    /**
     * Define the id_token_hint parameter
     * This value is the last issued ID Token, to identify the user
     *
     * @param IdToken|string $idToken The ID Token raw value, or object
     *
     * @return static
     */
    public function idToken($idToken): self
    {
        return $this->set('id_token_hint', (string) $idToken);
    }

    /**
     * The target URI which the OP should redirect after a successfully logout
     *
     * @param string $uri The redirect URI
     * @param string|null $state A random CSRF string, which should be returned by the OP on the redirect uri
     *
     * @return static
     */
    public function redirectUri(string $uri, ?string $state = null): self
    {
        $endpoint = $this->set('post_logout_redirect_uri', $uri);

        if ($state) {
            $endpoint = $endpoint->set('state', $state);
        }

        return $endpoint;
    }

    /**
     * {@inheritdoc}
     */
    public function apply(EndPointTransformerInterface $transformer)
    {
        return $transformer->onEndSession($this);
    }

    /**
     * Generates the end session URI
     *
     * @return string
     * @throws UnsupportedServerOperation
     */
    public function uri(): string
    {
        return $this->client->endPoints()->uri($this);
    }
}
