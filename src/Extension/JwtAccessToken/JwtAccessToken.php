<?php

namespace Parroauth2\Client\Extension\JwtAccessToken;

use Parroauth2\Client\Client;
use Parroauth2\Client\ClientInterface;
use Parroauth2\Client\Extension\ExtensionInterface;

/**
 * Enable JWT access token handling for introspection
 */
final class JwtAccessToken implements ExtensionInterface
{
    /**
     * @var JwtParserInterface
     */
    private $parser;

    /**
     * JwtAccessToken constructor.
     *
     * @param JwtParserInterface $parser
     */
    public function __construct(JwtParserInterface $parser = null)
    {
        $this->parser = $parser ?: new JwtParser();
    }

    /**
     * {@inheritdoc}
     */
    public function configure(ClientInterface $client): void
    {
        $client->endPoints()->add(new LocalIntrospectionEndPoint($client, $this->parser));
    }
}
