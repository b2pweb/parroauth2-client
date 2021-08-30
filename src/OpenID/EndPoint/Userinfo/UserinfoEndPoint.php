<?php

namespace Parroauth2\Client\OpenID\EndPoint\Userinfo;

use BadMethodCallException;
use InvalidArgumentException;
use Parroauth2\Client\ClientInterface;
use Parroauth2\Client\EndPoint\CallableEndPointInterface;
use Parroauth2\Client\EndPoint\EndPointParametersTrait;
use Parroauth2\Client\EndPoint\EndPointResponseListenerTrait;
use Parroauth2\Client\EndPoint\EndPointTransformerInterface;
use Psr\Http\Message\RequestInterface;

/**
 * Endpoint for get information about the user of the access token
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
 *
 * @implements CallableEndPointInterface<UserinfoResponse>
 */
class UserinfoEndPoint implements CallableEndPointInterface
{
    use EndPointParametersTrait;
    /** @use EndPointResponseListenerTrait<UserinfoResponse> */
    use EndPointResponseListenerTrait;

    const NAME = 'userinfo';

    const AUTH_METHOD_HEADER = 'header';
    const AUTH_METHOD_BODY = 'body';
    const AUTH_METHOD_QUERY = 'query';

    /**
     * @var ClientInterface
     * @readonly
     */
    private $client;

    /**
     * The current access token
     *
     * @var string|null
     * @readonly
     */
    private $accessToken = null;

    /**
     * The authentication method to use
     * The value must be one of the AUTH_METHOD_* constants
     *
     * @var string
     * @readonly
     */
    private $method = self::AUTH_METHOD_HEADER;


    /**
     * UserinfoEndPoint constructor.
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
    public function apply(EndPointTransformerInterface $transformer)
    {
        return $transformer->onUserinfo($this);
    }

    /**
     * Set the access token
     *
     * @param string $token
     *
     * @return static
     *
     * @psalm-mutation-free
     */
    public function token(string $token): self
    {
        $endpoint = clone $this;

        $endpoint->accessToken = $token;

        return $endpoint;
    }

    /**
     * Define the authentication method for the bearer token
     *
     * @param string $method One of the UserinfoEndPoint::AUTH_METHOD_* constant
     *
     * @return static
     *
     * @psalm-mutation-free
     */
    public function authenticationMethod(string $method): self
    {
        $endpoint = clone $this;

        $endpoint->method = $method;

        return $endpoint;
    }

    /**
     * Provide the token into the authorization header (recommended)
     *
     * @return static
     *
     * @psalm-mutation-free
     */
    public function inHeader(): self
    {
        return $this->authenticationMethod(self::AUTH_METHOD_HEADER);
    }

    /**
     * Provide the token as a body parameter
     *
     * @return static
     *
     * @psalm-mutation-free
     */
    public function inBody(): self
    {
        return $this->authenticationMethod(self::AUTH_METHOD_BODY);
    }

    /**
     * Provide the token as a query parameter (not recommended)
     *
     * @return static
     *
     * @psalm-mutation-free
     */
    public function inQuery(): self
    {
        return $this->authenticationMethod(self::AUTH_METHOD_QUERY);
    }

    /**
     * {@inheritdoc}
     *
     * @todo handle the JWT response
     */
    public function call(): UserinfoResponse
    {
        $response = $this->client->provider()->sendRequest($this->request());
        $contentType = strtolower(trim(explode(';', $response->getHeaderLine('Content-Type'))[0]));

        switch ($contentType) {
            case 'application/json':
                $response = new UserinfoResponse(json_decode((string) $response->getBody(), true));
                break;

            default:
                throw new BadMethodCallException('The Content-Type '.$contentType.' is not supported');
        }

        $this->callResponseListeners($response);
        return $response;
    }

    /**
     * Get the request for the userinfo endpoint
     * Define the token parameter following the Bearer token usage
     *
     * @return RequestInterface
     * @throws \Parroauth2\Client\Exception\UnsupportedServerOperation
     */
    private function request(): RequestInterface
    {
        if (!$this->accessToken) {
            throw new BadMethodCallException('No access token has been provided');
        }

        switch ($this->method) {
            // @see https://tools.ietf.org/html/rfc6750#section-2.1
            case self::AUTH_METHOD_HEADER:
                return $this->client->endPoints()
                    ->request('GET', $this)
                    ->withHeader('Authorization', 'Bearer '.$this->accessToken)
                ;

            // @see https://tools.ietf.org/html/rfc6750#section-2.2
            case self::AUTH_METHOD_BODY:
                return $this->client->endPoints()->request('POST', $this->set('access_token', $this->accessToken));

            // @see https://tools.ietf.org/html/rfc6750#section-2.3
            case self::AUTH_METHOD_QUERY:
                return $this->client->endPoints()
                    ->request('GET', $this->set('access_token', $this->accessToken))
                    ->withHeader('Cache-Control', 'no-store')
                ;

            default:
                throw new InvalidArgumentException('Unsupported authorization method '.$this->method);
        }
    }
}
