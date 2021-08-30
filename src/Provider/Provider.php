<?php

namespace Parroauth2\Client\Provider;

use Http\Client\HttpClient;
use Http\Message\RequestFactory;
use Jose\Component\Core\JWKSet;
use Parroauth2\Client\Client;
use Parroauth2\Client\ClientConfig;
use Parroauth2\Client\ClientInterface;
use Parroauth2\Client\Exception\OAuthServerException;
use Parroauth2\Client\Exception\Parroauth2Exception;
use Parroauth2\Client\Exception\UnsupportedServerOperation;
use Parroauth2\Client\Factory\ClientFactoryInterface;
use Psr\Http\Message\RequestInterface;

/**
 * The authorization provider
 *
 * Handle the HTTP operations, and create clients
 */
final class Provider implements ProviderInterface
{
    /**
     * @var ClientFactoryInterface
     */
    private $clientFactory;

    /**
     * @var HttpClient
     */
    private $httpClient;

    /**
     * @var RequestFactory
     */
    private $requestFactory;

    /**
     * @var ProviderConfig
     */
    private $config;


    /**
     * Provider constructor.
     *
     * @param ClientFactoryInterface $clientFactory
     * @param HttpClient $httpClient
     * @param RequestFactory $requestFactory
     * @param ProviderConfig $config
     */
    public function __construct(ClientFactoryInterface $clientFactory, HttpClient $httpClient, RequestFactory $requestFactory, ProviderConfig $config)
    {
        $this->clientFactory = $clientFactory;
        $this->httpClient = $httpClient;
        $this->requestFactory = $requestFactory;
        $this->config = $config;
    }

    /**
     * {@inheritdoc}
     */
    public function openid(): bool
    {
        return $this->config->openid();
    }

    /**
     * {@inheritdoc}
     */
    public function issuer(): string
    {
        return $this->metadata('issuer') ?: $this->config->url();
    }

    /**
     * {@inheritdoc}
     */
    public function metadata(string $parameter, $default = null)
    {
        return $this->config[$parameter] ?? $default;
    }

    /**
     * {@inheritdoc}
     */
    public function supportsEndpoint(string $name): bool
    {
        return isset($this->config[$name.'_endpoint']);
    }

    /**
     * {@inheritdoc}
     */
    public function uri($name, array $queryParameters = []): string
    {
        if (!$this->supportsEndpoint($name)) {
            throw new UnsupportedServerOperation('The endpoint "'.$name.'" is not supported by the authorization provider');
        }

        $baseUri = $this->config[$name.'_endpoint'];

        if (empty($queryParameters)) {
            return $baseUri;
        }

        return $baseUri.(strpos($baseUri, '?') === false ? '?' : '&').http_build_query($queryParameters);
    }

    /**
     * {@inheritdoc}
     */
    public function request(string $method, string $endpoint, array $queryParameters = [], $body = null): RequestInterface
    {
        if (is_array($body) || is_object($body)) {
            $body = http_build_query($body);
        }

        return $this->requestFactory->createRequest(
            $method,
            $this->uri($endpoint, $queryParameters),
            [],
            $body
        );
    }

    /**
     * {@inheritdoc}
     *
     * @throws Parroauth2Exception When a server error occurs
     */
    public function sendRequest(RequestInterface $request)
    {
        $response = $this->httpClient->sendRequest($request);

        if (!in_array(intdiv($response->getStatusCode(), 100), [4, 5])) {
            return $response;
        }

        $body = json_decode((string) $response->getBody(), true);

        if (!$body) {
            throw new Parroauth2Exception('An error has occurred:' . PHP_EOL . $response->getBody());
        }

        if (is_string($body)) {
            throw new Parroauth2Exception($body);
        }

        if (is_array($body) && isset($body['error'])) {
            if (!is_string($body['error'])) {
                throw new Parroauth2Exception('An error has occurred:' . PHP_EOL . print_r($body['error'], true));
            } else {
                throw OAuthServerException::create(
                    $body['error'],
                    $body['error_description'] ?? null,
                    $body['hint'] ?? null
                );
            }
        }

        throw new Parroauth2Exception('An error has occurred');
    }

    /**
     * {@inheritdoc}
     */
    public function client(ClientConfig $config): ClientInterface
    {
        return $this->clientFactory->create($this, $config);
    }

    /**
     * {@inheritdoc}
     */
    public function keySet(): JWKSet
    {
        if (isset($this->config['jwks'])) {
            return $this->config['jwks'];
        }

        if (!isset($this->config['jwks_uri'])) {
            throw new \LogicException('Cannot get key set : neither jwks nor jwks_uri are configured');
        }

        $response = $this->sendRequest($this->requestFactory->createRequest('GET', $this->config['jwks_uri']));

        return $this->config['jwks'] = JWKSet::createFromJson((string) $response->getBody());
    }
}
