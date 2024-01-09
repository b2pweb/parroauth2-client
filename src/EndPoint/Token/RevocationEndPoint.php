<?php

namespace Parroauth2\Client\EndPoint\Token;

use Parroauth2\Client\Authentication\ClientAuthenticationMethodInterface;
use Parroauth2\Client\ClientInterface;
use Parroauth2\Client\EndPoint\CallableEndPointInterface;
use Parroauth2\Client\EndPoint\EndPointParametersTrait;
use Parroauth2\Client\EndPoint\EndPointResponseListenerTrait;
use Parroauth2\Client\EndPoint\EndPointTransformerInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * The token revocation endpoint
 *
 * @see https://tools.ietf.org/html/rfc7009
 *
 * @implements CallableEndPointInterface<ResponseInterface>
 */
class RevocationEndPoint implements CallableEndPointInterface
{
    use EndPointParametersTrait;
    /** @use EndPointResponseListenerTrait<ResponseInterface> */
    use EndPointResponseListenerTrait;

    public const NAME = 'revocation';

    public const TYPE_ACCESS_TOKEN = 'access_token';
    public const TYPE_REFRESH_TOKEN = 'refresh_token';

    /**
     * @var ClientInterface
     * @readonly
     */
    private $client;


    /**
     * RevocationEndPoint constructor.
     *
     * @param ClientInterface $client
     */
    public function __construct(ClientInterface $client)
    {
        $this->client = $client;
    }

    /**
     * {@inheritdoc}
     *
     * @psalm-mutation-free
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
     * @return static
     *
     * @psalm-mutation-free
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
     * @return static
     *
     * @psalm-mutation-free
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
     * @return static
     *
     * @psalm-mutation-free
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
     * @return static
     *
     * @psalm-mutation-free
     */
    public function refreshToken(string $token): RevocationEndPoint
    {
        return $this->token($token)->typeHint(self::TYPE_REFRESH_TOKEN);
    }

    /**
     * {@inheritdoc}
     */
    public function call(): ResponseInterface
    {
        $client = $this->client;
        $endPoints = $client->endPoints();
        $request = $endPoints->request('POST', $this);
        $authenticationMethod = $endPoints->authenticationMethod($this->name(), $client->option(ClientAuthenticationMethodInterface::OPTION_PREFERRED_METHOD));

        $request = $authenticationMethod->apply($client, $request);

        $response = $this->client->provider()->sendRequest($request);
        $this->callResponseListeners($response);

        return $response;
    }
}
