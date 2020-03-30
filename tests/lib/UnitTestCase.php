<?php

namespace Parroauth2\Client\Tests;

use Bdf\PHPUnit\TestCase;
use Http\Discovery\MessageFactoryDiscovery;
use Http\Mock\Client;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use Parroauth2\Client\Factory\BaseClientFactory;
use Parroauth2\Client\Provider\Provider;
use Parroauth2\Client\Provider\ProviderLoader;
use Parroauth2\Client\Storage\ArrayStorage;

/**
 * Class UnitTestCase
 */
class UnitTestCase extends TestCase
{
    /**
     * @var ArrayStorage
     */
    protected $session;

    /**
     * @var Client
     */
    protected $httpClient;

    protected function setUp(): void
    {
        $this->session = new ArrayStorage();
        $this->httpClient = new Client();
    }

    public function provider(array $parameters = [], bool $openid = true): Provider
    {
        $loader = new ProviderLoader(new BaseClientFactory($this->session), $this->httpClient);

        return $loader->create($parameters + [
            'issuer'                 => 'http://op.example.com',
            'authorization_endpoint' => 'http://op.example.com/authorize',
            'token_endpoint'         => 'http://op.example.com/token',
            'revocation_endpoint'    => 'http://op.example.com/revoke',
            'userinfo_endpoint'    => 'http://op.example.com/userinfo',
            'introspection_endpoint'    => 'http://op.example.com/introspection',
            'jwks'                   => new JWKSet([
                JWKFactory::createFromKeyFile(__DIR__.'/../keys/oauth-public.key', null, ['use' => 'sig', 'alg' => 'RS256']),
            ])
        ], $openid);
    }
}
