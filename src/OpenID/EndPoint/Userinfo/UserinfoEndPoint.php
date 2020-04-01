<?php

namespace Parroauth2\Client\OpenID\EndPoint\Userinfo;

use Parroauth2\Client\Client;
use Parroauth2\Client\ClientInterface;
use Parroauth2\Client\EndPoint\EndPointInterface;
use Parroauth2\Client\EndPoint\EndPointParametersTrait;
use Parroauth2\Client\EndPoint\EndPointTransformerInterface;
use Psr\Http\Message\RequestInterface;

/**
 * Endpoint for get information about the user of the access token
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
 */
class UserinfoEndPoint implements EndPointInterface
{
    use EndPointParametersTrait;

    const NAME = 'userinfo';

    const AUTH_METHOD_HEADER = 'header';
    const AUTH_METHOD_BODY = 'body';
    const AUTH_METHOD_QUERY = 'query';

    /**
     * @var ClientInterface
     */
    private $client;

    /**
     * The current access token
     *
     * @var string
     */
    private $accessToken;

    /**
     * The authentication method to use
     * The value must be one of the AUTH_METHOD_* constants
     *
     * @var string
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
     * @return $this
     */
    public function inHeader(): self
    {
        return $this->authenticationMethod(self::AUTH_METHOD_HEADER);
    }

    /**
     * Provide the token as a body parameter
     *
     * @return $this
     */
    public function inBody(): self
    {
        return $this->authenticationMethod(self::AUTH_METHOD_BODY);
    }

    /**
     * Provide the token as a query parameter (not recommended)
     *
     * @return $this
     */
    public function inQuery(): self
    {
        return $this->authenticationMethod(self::AUTH_METHOD_QUERY);
    }

    /**
     * Call the endpoint
     *
     * @return UserinfoResponse
     *
     * @throws \Http\Client\Exception
     * @throws \Parroauth2\Client\Exception\Parroauth2Exception
     * @throws \Parroauth2\Client\Exception\UnsupportedServerOperation
     *
     * @todo handle the JWT response
     */
    public function call(): UserinfoResponse
    {
        $response = $this->client->provider()->sendRequest($this->request());
        $contentType = strtolower(trim(explode(';', $response->getHeaderLine('Content-Type'))[0]));

        switch ($contentType) {
            case 'application/json':
                return new UserinfoResponse(json_decode($response->getBody(), true));

            default:
                throw new \BadMethodCallException('The Content-Type '.$contentType.' is not supported');
        }
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
                throw new \InvalidArgumentException('Unsupported authorization method '.$this->method);
        }
    }
}
