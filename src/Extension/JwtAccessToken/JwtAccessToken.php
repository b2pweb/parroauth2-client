<?php

namespace Parroauth2\Client\Extension\JwtAccessToken;

use Parroauth2\Client\Client;
use Parroauth2\Client\ClientInterface;
use Parroauth2\Client\Extension\ExtensionInterface;
use Parroauth2\Client\Util\NativeClock;
use Psr\Clock\ClockInterface;

/**
 * Enable JWT access token handling for introspection
 */
final class JwtAccessToken implements ExtensionInterface
{
    private readonly JwtParserInterface $parser;
    private readonly ClockInterface $clock;

    /**
     * JwtAccessToken constructor.
     *
     * @param JwtParserInterface|null $parser
     * @param ClockInterface|null $clock
     */
    public function __construct(?JwtParserInterface $parser = null, ?ClockInterface $clock = null)
    {
        $this->parser = $parser ?? new JwtParser();
        $this->clock = $clock ?? NativeClock::instance();
    }

    /**
     * {@inheritdoc}
     */
    public function configure(ClientInterface $client): void
    {
        $client->endPoints()->add(new LocalIntrospectionEndPoint($client, $this->parser, $this->clock));
    }
}
