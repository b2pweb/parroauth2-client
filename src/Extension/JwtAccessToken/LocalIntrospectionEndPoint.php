<?php

namespace Parroauth2\Client\Extension\JwtAccessToken;

use Parroauth2\Client\ClientInterface;
use Parroauth2\Client\EndPoint\Introspection\IntrospectionEndPoint;
use Parroauth2\Client\EndPoint\Introspection\IntrospectionResponse;

/**
 * Try to perform a local introspection by deserialize a JWT access token
 * If the deserialization failed, the base introspection endpoint will be called
 */
class LocalIntrospectionEndPoint extends IntrospectionEndPoint
{
    /**
     * @var JwtParserInterface
     */
    private $parser;

    /**
     * @var ClientInterface
     */
    private $client;


    /**
     * LocalIntrospectionEndPoint constructor.
     *
     * @param ClientInterface $client
     * @param JwtParserInterface $parser
     */
    public function __construct(ClientInterface $client, JwtParserInterface $parser)
    {
        parent::__construct($client);

        $this->parser = $parser;
        $this->client = $client;
    }

    /**
     * {@inheritdoc}
     */
    public function call(): IntrospectionResponse
    {
        if ($this->get('token_type_hint') !== null && $this->get('token_type_hint') !== self::TYPE_ACCESS_TOKEN) {
            return $this->networkCall();
        }

        try {
            $claims = $this->parser->parse($this->get('token'), $this->client);
        } catch (\InvalidArgumentException $e) {
            return $this->networkCall();
        }

        $expired = $claims['exp'] ?? 0;

        $claims += ['token_type' => 'bearer', 'iss' => null];

        if (!isset($claims['client_id']) && !empty($claims['aud'])) {
            $claims['client_id'] = is_array($claims['aud']) ? $claims['aud'][0] : $claims['aud'];
        }

        // We check here if the issuer is right and if the token is not expired
        if ($claims['iss'] !== $this->client->provider()->issuer() || ($expired >= 0 && $expired < time())) {
            $response = new IntrospectionResponse(['active' => false]);
        } else {
            $response = new IntrospectionResponse(['active' => true] + $claims);
        }

        $this->callResponseListeners($response);

        return $response;
    }

    /**
     * Try to call the endpoint, if configured
     * If not, an inactive introspection response is returned
     */
    private function networkCall(): IntrospectionResponse
    {
        if ($this->client->provider()->supportsEndpoint(self::NAME)) {
            return parent::call();
        }

        $response = new IntrospectionResponse(['active' => false]);
        $this->callResponseListeners($response);

        return $response;
    }
}
