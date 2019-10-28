<?php

namespace Parroauth2\Client\EndPoint\Token;

use Http\Client\Exception;
use Parroauth2\Client\Client;
use Parroauth2\Client\EndPoint\EndPointInterface;
use Parroauth2\Client\EndPoint\EndPointParametersTrait;
use Parroauth2\Client\EndPoint\EndPointResponseListenerTrait;
use Parroauth2\Client\EndPoint\EndPointTransformerInterface;
use Parroauth2\Client\Exception\Parroauth2Exception;

/**
 * The token revocation endpoint
 *
 * @see https://tools.ietf.org/html/rfc7009
 */
class RevocationEndPoint implements EndPointInterface
{
    use EndPointParametersTrait;
    use EndPointResponseListenerTrait;

    const NAME = 'revocation';

    const TYPE_ACCESS_TOKEN = 'access_token';
    const TYPE_REFRESH_TOKEN = 'refresh_token';

    /**
     * @var Client
     */
    private $client;


    /**
     * RevocationEndPoint constructor.
     *
     * @param Client $client
     */
    public function __construct(Client $client)
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
     * {@inheritdoc}
     */
    public function apply(EndPointTransformerInterface $transformer): RevocationEndPoint
    {
        return $transformer->onRevocation($this);
    }

    /**
     * Define the token to revoke
     *
     * @param string $token Token to revoke. May be an access token or a refresh token
     *
     * @return RevocationEndPoint
     */
    public function token(string $token): RevocationEndPoint
    {
        return $this->set('token', $token);
    }

    /**
     * Define the token type
     * The server can ignore this value if not match with the token
     *
     * @param string $type the token type
     *
     * @return RevocationEndPoint
     */
    public function typeHint(string $type): RevocationEndPoint
    {
        return $this->set('token_type_hint', $type);
    }

    /**
     * Try to revoke an access token
     *
     * @param string $token The access token
     *
     * @return RevocationEndPoint
     */
    public function accessToken(string $token): RevocationEndPoint
    {
        return $this->token($token)->typeHint(self::TYPE_ACCESS_TOKEN);
    }

    /**
     * Try to revoke a refresh token
     *
     * @param string $token The refresh token
     *
     * @return RevocationEndPoint
     */
    public function refreshToken(string $token): RevocationEndPoint
    {
        return $this->token($token)->typeHint(self::TYPE_REFRESH_TOKEN);
    }

    /**
     * Call the endpoint
     *
     * @throws Parroauth2Exception When an error occurs during execution
     * @throws Exception
     *
     * @todo Handle other client credentials
     */
    public function call(): void
    {
        $request = $this->client->endPoints()
            ->request('POST', $this)
            ->withHeader('Authorization', 'Basic '.base64_encode($this->client->clientId().':'.$this->client->secret()))
        ;

        $this->callResponseListeners($this->client->provider()->sendRequest($request));
    }
}
