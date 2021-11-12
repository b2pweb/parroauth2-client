<?php

/**
 * Server side implementation for validate the token
 */

use Parroauth2\Client\ClientConfig;
use Parroauth2\Client\EndPoint\Introspection\IntrospectionResponse;
use Parroauth2\Client\Extension\JwtAccessToken\JwtAccessToken;
use Parroauth2\Client\Extension\RequiredScopeValidator;
use Parroauth2\Client\Provider\ProviderConfigPool;
use Parroauth2\Client\Provider\ProviderLoader;
use Psr\SimpleCache\CacheInterface;

require_once __DIR__.'/../vendor/autoload.php';

class Authenticator
{
    private const PROVIDER_URL = 'http://192.168.0.139/~vquatrevieux/sso/s2pweb/oidc';
    private const CLIENT_ID = 'server_resource_test';
    private const CLIENT_SECRET = 'my_secret';

    /**
     * @var \Parroauth2\Client\ClientInterface
     */
    private $client;

    /**
     * @var IntrospectionResponse
     */
    private $token;

    public function __construct(CacheInterface $cache)
    {
        // Load the provider and provide a cache for the config to ensure that
        // keys and config are stored locally, and the server will not perform any request to check the token
        $loader = new ProviderLoader(null, null, null, null, new ProviderConfigPool($cache));

        // Create the client
        $this->client = $loader->discover(self::PROVIDER_URL)->client(
            (new ClientConfig(self::CLIENT_ID))->setSecret(self::CLIENT_SECRET)
        );

        // Enable local introspection using JWT access token
        $this->client->register(new JwtAccessToken());

        // Resource owner should check for some required scopes.
        // Enable this extension to assert the given scope are provided in the access token.
        $this->client->register(new RequiredScopeValidator(['profile']));
    }

    /**
     * Validate the access token passed as "Authorization: Bearer" header
     *
     * Perform a local introspection if possible (a key has been configured, and the access token is effectively a JWT)
     *
     * @return bool true if the access token is valid
     *
     * @throws \Http\Client\Exception
     * @throws \Parroauth2\Client\Exception\Parroauth2Exception
     * @throws \Parroauth2\Client\Exception\UnsupportedServerOperation
     *
     * @psalm-assert-if-true !null $this->token()
     * @psalm-assert-if-fale null $this->token()
     */
    public function authenticate(): bool
    {
        // Check the Authorization header
        if (empty($_SERVER['HTTP_AUTHORIZATION'])) {
            return false;
        }

        $header = explode(' ', trim($_SERVER['HTTP_AUTHORIZATION']));

        if (count($header) !== 2 || strcasecmp($header[0], 'bearer') !== 0) {
            return false;
        }

        // Perform introspection on the token
        // No HTTP request should be performed here because local introspection is enabled
        $response = $this->client->endPoints()->introspection()
            ->accessToken($header[1])
            ->call()
        ;

        // The token is expired or invalid
        if (!$response->active()) {
            return false;
        }

        $this->token = $response;

        return true;
    }

    /**
     * Get the parsed token
     *
     * @return IntrospectionResponse|null
     */
    public function token(): ?IntrospectionResponse
    {
        return $this->token;
    }
}

$authenticator = new Authenticator(new MyCacheImplementation());

if (!$authenticator->authenticate()) {
    http_response_code(401);
    exit('Invalid access token');
}

// Get the user id from the token
$userId = $authenticator->token()->subject();

echo json_encode(loadFromUserId($userId));
