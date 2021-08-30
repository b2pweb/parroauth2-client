<?php

namespace Parroauth2\Client;

use Jose\Component\Core\JWKSet;
use Parroauth2\Client\EndPoint\EndPoints;
use Parroauth2\Client\Extension\ExtensionInterface;
use Parroauth2\Client\Provider\ProviderInterface;
use Parroauth2\Client\Storage\StorageInterface;

/**
 * The oauth2 client
 */
class Client implements ClientInterface
{
    /**
     * @var ProviderInterface
     */
    private $provider;

    /**
     * @var ClientConfig
     */
    private $clientConfig;

    /**
     * @var EndPoints
     */
    private $endPoints;

    /**
     * @var StorageInterface
     */
    private $session;


    /**
     * Client constructor.
     *
     * @param ProviderInterface $provider
     * @param ClientConfig $clientConfig
     * @param StorageInterface $session
     */
    public function __construct(ProviderInterface $provider, ClientConfig $clientConfig, StorageInterface $session)
    {
        $this->provider = $provider;
        $this->clientConfig = $clientConfig;
        $this->endPoints = new EndPoints($provider);
        $this->session = $session;
    }

    /**
     * Get the client id
     *
     * @return string
     */
    public function clientId(): string
    {
        return $this->clientConfig->clientId();
    }

    /**
     * Get the client secret.
     * May be null on a public client configuration
     *
     * @return string|null
     */
    public function secret(): ?string
    {
        return $this->clientConfig->secret();
    }

    /**
     * Get the client data storage
     *
     * @return StorageInterface
     */
    public function storage(): StorageInterface
    {
        return $this->session;
    }

    /**
     * Get the configuration of the client
     *
     * @return ClientConfig
     */
    public function clientConfig(): ClientConfig
    {
        return $this->clientConfig;
    }

    /**
     * Get the authorization provider
     *
     * @return ProviderInterface
     */
    public function provider(): ProviderInterface
    {
        return $this->provider;
    }

    /**
     * @return EndPoints
     */
    public function endPoints(): EndPoints
    {
        return $this->endPoints;
    }

    /**
     * Get the key set for the client
     *
     * @return JWKSet
     */
    public function keySet(): JWKSet
    {
        if ($jwks = $this->clientConfig->option('jwks')) {
            return $jwks;
        }

        return $this->provider->keySet();
    }

    /**
     * Get an option from client or provider
     *
     * @param string $name The option name
     * @param T|null $default The default value to return when not found on client and provider parameters
     *
     * @return T|null
     *
     * @template T
     */
    public function option(string $name, $default = null)
    {
        return $this->clientConfig->option($name, $this->provider->metadata($name, $default));
    }

    /**
     * Register extension
     *
     * @param ExtensionInterface $extension
     */
    public function register(ExtensionInterface $extension): void
    {
        $extension->configure($this);
    }

    /**
     * Request for token from username / password
     *
     * @param string $username
     * @param string $password
     * @param null|string[] $scopes
     * 
     * @return Authorization
     *
     * @deprecated Use token endpoint
     * @psalm-suppress DeprecatedClass
     */
    public function login($username, $password, array $scopes = null)
    {
        return Authorization::fromTokenResponse($this->endPoints->token()->password($username, $password, $scopes)->call());
    }

    /**
     * {@inheritdoc}
     *
     * @deprecated Use token endpoint
     * @psalm-suppress DeprecatedClass
     */
    public function refresh($token, array $scopes = null)
    {
        if ($token instanceof Authorization) {
            $token = $token->refreshToken();
        }

        /** @psalm-suppress PossiblyNullArgument */
        return Authorization::fromTokenResponse($this->endPoints->token()->refresh($token, $scopes)->call());
    }

    /**
     * Request the token from authorization code
     *
     * @param string $code
     * @param null|string $redirectUri
     * @param null|string $clientId
     *
     * @return Authorization
     *
     * @deprecated Use AuthorizationCodeFlow or token endpoint
     * @psalm-suppress DeprecatedClass
     */
    public function tokenFromAuthorizationCode($code, $redirectUri = null, $clientId = null)
    {
        return Authorization::fromTokenResponse($this->endPoints->token()->code($code, $redirectUri)->call());
    }

    /**
     * Get the authorization uri
     *
     * @param string $redirectUri
     * @param null|string[] $scopes
     * @param null|string $state
     * @param null|string $clientId
     * @param array<string, mixed> $parameters
     *
     * @return string
     *
     * @deprecated Use AuthorizationCodeFlow or authorization endpoint
     * @psalm-suppress DeprecatedClass
     */
    public function getAuthorizationUri($redirectUri, array $scopes = null, $state = null, $clientId = null, array $parameters = [])
    {
        $endpoint = $this->endPoints->authorization()->code($redirectUri, $scopes ?: []);

        if ($state) {
            $endpoint = $endpoint->state($state);
        }

        if ($clientId !== null) {
            $parameters['client_id'] = $clientId;
        }

        foreach ($parameters as $key => $value) {
            $endpoint = $endpoint->set($key, $value);
        }

        return $endpoint->uri();
    }

    /**
     * Introspect a token
     *
     * @param Authorization|string $token
     * @param string $hint
     * 
     * @return Introspection
     *
     * @deprecated Use introspection endpoint
     * @psalm-suppress DeprecatedClass
     */
    public function introspect($token, $hint = null)
    {
        if ($token instanceof Authorization) {
            if ($hint === null || $hint === Authorization::ACCESS_TOKEN) {
                $token = $token->accessToken();
            } else {
                $token = $token->refreshToken();
            }
        }

        /** @psalm-suppress PossiblyNullArgument */
        $endpoint = $this->endPoints->introspection()->token($token);

        if ($hint) {
            $endpoint = $endpoint->typeHint($hint);
        }

        return Introspection::fromResponse($endpoint->call());
    }

    /**
     * Revoke the token
     *
     * @param Authorization|string $token
     * @param string $hint
     *
     * @return void
     *
     * @deprecated Use revocation endpoint
     * @psalm-suppress DeprecatedClass
     */
    public function revoke($token, $hint = null)
    {
        if ($token instanceof Authorization) {
            if ($hint === null || $hint === Authorization::ACCESS_TOKEN) {
                $token = $token->accessToken();
            } else {
                $token = $token->refreshToken();
            }
        }

        /** @psalm-suppress PossiblyNullArgument */
        $endpoint = $this->endPoints->revocation()->token($token);

        if ($hint) {
            $endpoint = $endpoint->typeHint($hint);
        }

        $endpoint->call();
    }

    /**
     * Gets user info from the access token
     *
     * @param string|Authorization $token
     *
     * @return Userinfo
     *
     * @deprecated Use userinfo endpoint
     * @psalm-suppress DeprecatedClass
     */
    public function userinfo($token)
    {
        if ($token instanceof Authorization) {
            $token = $token->accessToken();
        }

        return Userinfo::fromResponse($this->endPoints->userinfo()->token($token)->call());
    }
}
