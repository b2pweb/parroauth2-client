<?php

namespace Parroauth2\Client\EndPoint\Introspection;

use Parroauth2\Client\Authentication\ClientAuthenticationMethodInterface;
use Parroauth2\Client\ClientInterface;
use Parroauth2\Client\EndPoint\CallableEndPointInterface;
use Parroauth2\Client\EndPoint\EndPointParametersTrait;
use Parroauth2\Client\EndPoint\EndPointResponseListenerTrait;
use Parroauth2\Client\EndPoint\EndPointTransformerInterface;

/**
 * Handle the token introspection
 * The introspection permit to get meta-information about the current token
 *
 * @see https://tools.ietf.org/html/rfc7662
 *
 * @implements CallableEndPointInterface<IntrospectionResponse>
 */
class IntrospectionEndPoint implements CallableEndPointInterface
{
    use EndPointParametersTrait;
    /** @use EndPointResponseListenerTrait<IntrospectionResponse> */
    use EndPointResponseListenerTrait;

    public const NAME = 'introspection';

    public const TYPE_ACCESS_TOKEN = 'access_token';
    public const TYPE_REFRESH_TOKEN = 'refresh_token';

    /**
     * @var ClientInterface
     * @readonly
     */
    private $client;

    /**
     * IntrospectionEndPoint constructor.
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
    public function apply(EndPointTransformerInterface $transformer): IntrospectionEndPoint
    {
        return $transformer->onIntrospection($this);
    }

    /**
     * Define the token
     *
     * @param string $token Token to revoke. May be an access token or a refresh token
     *
     * @return static
     *
     * @psalm-mutation-free
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
     * @return static
     *
     * @psalm-mutation-free
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
     * @return static
     *
     * @psalm-mutation-free
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
     * @return static
     *
     * @psalm-mutation-free
     */
    public function refreshToken(string $token): IntrospectionEndPoint
    {
        return $this->token($token)->typeHint(self::TYPE_REFRESH_TOKEN);
    }

    /**
     * {@inheritdoc}
     */
    public function call(): IntrospectionResponse
    {
        $client = $this->client;
        $endPoints = $client->endPoints();
        $request = $endPoints->request('POST', $this);
        $authenticationMethod = $endPoints->authenticationMethod($this->name(), $client->option(ClientAuthenticationMethodInterface::OPTION_PREFERRED_METHOD));

        $request = $authenticationMethod->apply($client, $request);

        $body = (string) $this->client->provider()->sendRequest($request)->getBody();
        $response = new IntrospectionResponse(json_decode($body, true));

        $this->callResponseListeners($response);

        return $response;
    }
}
