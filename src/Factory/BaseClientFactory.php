<?php

namespace Parroauth2\Client\Factory;

use Parroauth2\Client\Client;
use Parroauth2\Client\ClientConfig;
use Parroauth2\Client\ClientInterface;
use Parroauth2\Client\EndPoint\Authorization\AuthorizationEndPoint;
use Parroauth2\Client\EndPoint\Introspection\IntrospectionEndPoint;
use Parroauth2\Client\EndPoint\Token\RevocationEndPoint;
use Parroauth2\Client\EndPoint\Token\TokenEndPoint;
use Parroauth2\Client\OpenID\EndPoint\AuthorizationEndPoint as OpenIdAuthorizationEndPoint;
use Parroauth2\Client\OpenID\EndPoint\Token\TokenEndPoint as OpenIdTokenEndPoint;
use Parroauth2\Client\OpenID\EndPoint\Userinfo\UserinfoEndPoint;
use Parroauth2\Client\OpenID\IdToken\IdTokenParserInterface;
use Parroauth2\Client\OpenID\IdToken\JwsIdTokenParser;
use Parroauth2\Client\Provider\Provider;
use Parroauth2\Client\Provider\ProviderInterface;
use Parroauth2\Client\Storage\ArrayStorage;
use Parroauth2\Client\Storage\StorageInterface;

/**
 * Client factory which detect if openid is enabled, and register the corresponding endpoints
 */
final class BaseClientFactory implements ClientFactoryInterface
{
    /**
     * @var StorageInterface
     */
    private $storage;

    /**
     * @var EndPointConfigurator
     */
    private $oauthConfigurator;

    /**
     * @var EndPointConfigurator
     */
    private $openidConfigurator;

    /**
     * @var IdTokenParserInterface|null
     */
    private $idTokenParser;


    /**
     * BaseClientFactory constructor.
     *
     * @param StorageInterface $storage
     * @param IdTokenParserInterface|null $idTokenParser
     */
    public function __construct(StorageInterface $storage = null, IdTokenParserInterface $idTokenParser = null)
    {
        $this->storage = $storage ?: new ArrayStorage();
        $this->idTokenParser = $idTokenParser;

        $this->oauthConfigurator = new EndPointConfigurator($oauthEndpoints = [
            AuthorizationEndPoint::NAME => AuthorizationEndPoint::class,
            TokenEndPoint::NAME => TokenEndPoint::class,
            RevocationEndPoint::NAME => RevocationEndPoint::class,
            IntrospectionEndPoint::NAME => IntrospectionEndPoint::class,
        ]);

        $this->openidConfigurator = new EndPointConfigurator([
            OpenIdAuthorizationEndPoint::NAME => OpenIdAuthorizationEndPoint::class,
            OpenIdTokenEndPoint::NAME => function (ClientInterface $client) { return new OpenIdTokenEndPoint($client, $this->idTokenParser ?: new JwsIdTokenParser()); },
            UserinfoEndPoint::NAME => UserinfoEndPoint::class,
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
     * @param StorageInterface $storage
     */
    public function setStorage(StorageInterface $storage): void
    {
        $this->storage = $storage;
    }

    /**
     * @return IdTokenParserInterface|null
     */
    public function idTokenParser(): ?IdTokenParserInterface
    {
        return $this->idTokenParser;
    }

    /**
     * @param IdTokenParserInterface|null $idTokenParser
     */
    public function setIdTokenParser(?IdTokenParserInterface $idTokenParser): void
    {
        $this->idTokenParser = $idTokenParser;
    }
}
