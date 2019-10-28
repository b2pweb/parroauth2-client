<?php

namespace Parroauth2\Client\EndPoint\Introspection;

use Http\Client\Exception;
use Parroauth2\Client\Client;
use Parroauth2\Client\EndPoint\EndPointInterface;
use Parroauth2\Client\EndPoint\EndPointParametersTrait;
use Parroauth2\Client\EndPoint\EndPointResponseListenerTrait;
use Parroauth2\Client\EndPoint\EndPointTransformerInterface;
use Parroauth2\Client\Exception\Parroauth2Exception;

/**
 * Handle the token introspection
 * The introspection permit to get meta-information about the current token
 *
 * @see https://tools.ietf.org/html/rfc7662
 */
class IntrospectionEndPoint implements EndPointInterface
{
    use EndPointParametersTrait;
    use EndPointResponseListenerTrait;

    const NAME = 'introspection';

    const TYPE_ACCESS_TOKEN = 'access_token';
    const TYPE_REFRESH_TOKEN = 'refresh_token';

    /**
     * @var Client
     */
    private $client;

    /**
     * IntrospectionEndPoint constructor.
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
    public function apply(EndPointTransformerInterface $transformer): IntrospectionEndPoint
    {
        return $transformer->onIntrospection($this);
    }

    /**
     * Define the token
     *
     * @param string $token Token to revoke. May be an access token or a refresh token
     *
     * @return IntrospectionEndPoint
     */
    public function token(string $token): IntrospectionEndPoint
    {
        return $this->set('token', $token);
    }

    /**
     * Define the token type
     * The server can ignore this value if not match with the token
     *
     * @param string $type the token type
     *
     * @return IntrospectionEndPoint
     */
    public function typeHint(string $type): IntrospectionEndPoint
    {
        return $this->set('token_type_hint', $type);
    }

    /**
     * Request for an access token
     *
     * @param string $token The access token
     *
     * @return IntrospectionEndPoint
     */
    public function accessToken(string $token): IntrospectionEndPoint
    {
        return $this->token($token)->typeHint(self::TYPE_ACCESS_TOKEN);
    }

    /**
     * Request for a refresh token
     *
     * @param string $token The refresh token
     *
     * @return IntrospectionEndPoint
     */
    public function refreshToken(string $token): IntrospectionEndPoint
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
    public function call(): IntrospectionResponse
    {
        $request = $this->client->endPoints()
            ->request('POST', $this)
            ->withHeader('Authorization', 'Basic '.base64_encode($this->client->clientId().':'.$this->client->secret()))
        ;

        $response = new IntrospectionResponse(json_decode($this->client->provider()->sendRequest($request)->getBody(), true));

        $this->callResponseListeners($response);

        return $response;
    }
}
