<?php

namespace Parroauth2\Client\Extension\JwtAccessToken;

use Parroauth2\Client\Client;
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
            return parent::call();
        }

        try {
            $claims = $this->parser->parse($this->get('token'), $this->client);
        } catch (\InvalidArgumentException $e) {
            return parent::call();
        }

        $expired = $claims['exp'] ?? 0;

        $claims += ['token_type' => 'bearer'];

        if (!isset($claims['client_id']) && !empty($claims['aud'])) {
            $claims['client_id'] = is_array($claims['aud']) ? $claims['aud'][0] : $claims['aud'];
        }

        if ($expired >= 0 && $expired < time()) {
            $response = new IntrospectionResponse(['active' => false]);
        } else {
            $response = new IntrospectionResponse(['active' => true] + $claims);
        }

        $this->callResponseListeners($response);

        return $response;
    }
}
