<?php

namespace Parroauth2\Client\Factory;

use Parroauth2\Client\Client;
use Parroauth2\Client\ClientConfig;
use Parroauth2\Client\ClientInterface;
use Parroauth2\Client\EndPoint\Authorization\AuthorizationEndPoint;
use Parroauth2\Client\EndPoint\Introspection\IntrospectionEndPoint;
use Parroauth2\Client\EndPoint\Token\RevocationEndPoint;
use Parroauth2\Client\EndPoint\Token\TokenEndPoint;
use Parroauth2\Client\EndPoint\Token\TokenResponse;
use Parroauth2\Client\OpenID\EndPoint\AuthorizationEndPoint as OpenIdAuthorizationEndPoint;
use Parroauth2\Client\OpenID\EndPoint\EndSessionEndPoint;
use Parroauth2\Client\OpenID\EndPoint\Token\TokenEndPoint as OpenIdTokenEndPoint;
use Parroauth2\Client\OpenID\EndPoint\Userinfo\UserinfoEndPoint;
use Parroauth2\Client\OpenID\IdToken\IdTokenParserInterface;
use Parroauth2\Client\OpenID\IdToken\JwsIdTokenParser;
use Parroauth2\Client\Provider\ProviderInterface;
use Parroauth2\Client\Storage\ArrayStorage;
use Parroauth2\Client\Storage\StorageInterface;
use Parroauth2\Client\Util\NativeClock;
use Psr\Clock\ClockInterface;

/**
 * Client factory which detect if openid is enabled, and register the corresponding endpoints
 */
final class BaseClientFactory implements ClientFactoryInterface
{
    private readonly StorageInterface $storage;
    private readonly EndPointConfigurator $oauthConfigurator;
    private readonly EndPointConfigurator $openidConfigurator;
    private readonly ?IdTokenParserInterface $idTokenParser;
    private readonly ClockInterface $clock;

    /**
     * BaseClientFactory constructor.
     *
     * @param StorageInterface|null $storage
     * @param IdTokenParserInterface|null $idTokenParser
     */
    public function __construct(?StorageInterface $storage = null, ?IdTokenParserInterface $idTokenParser = null, ?ClockInterface $clock = null)
    {
        $this->storage = $storage ?? new ArrayStorage();
        $this->idTokenParser = $idTokenParser;
        $this->clock = $clock ?? NativeClock::instance();

        $this->oauthConfigurator = new EndPointConfigurator($oauthEndpoints = [
            AuthorizationEndPoint::NAME => AuthorizationEndPoint::class,
            TokenEndPoint::NAME => fn (ClientInterface $client) => new TokenEndPoint(
                $client,
                fn (array $response) => TokenResponse::create($response, $this->clock)
            ),
            RevocationEndPoint::NAME => RevocationEndPoint::class,
            IntrospectionEndPoint::NAME => IntrospectionEndPoint::class,
        ]);

        $this->openidConfigurator = new EndPointConfigurator([
            OpenIdAuthorizationEndPoint::NAME => OpenIdAuthorizationEndPoint::class,
            OpenIdTokenEndPoint::NAME => fn (ClientInterface $client) => new OpenIdTokenEndPoint(
                $client,
                $this->idTokenParser ?? new JwsIdTokenParser(),
                $this->clock,
            ),
            UserinfoEndPoint::NAME => UserinfoEndPoint::class,
            EndSessionEndPoint::NAME => EndSessionEndPoint::class,
        ] + $oauthEndpoints);
    }

    /**
     * {@inheritdoc}
     */
    public function create(ProviderInterface $provider, ClientConfig $config): ClientInterface
    {
        $client = new Client($provider, $config, $this->storage);

        if ($config->openid() && $provider->openid()) {
            $this->openidConfigurator->configure($client);
        } else {
            $this->oauthConfigurator->configure($client);
        }

        return $client;
    }

    /**
     * @return StorageInterface
     */
    public function storage(): StorageInterface
    {
        return $this->storage;
    }

    /**
     * @return IdTokenParserInterface|null
     */
    public function idTokenParser(): ?IdTokenParserInterface
    {
        return $this->idTokenParser;
    }
}
