<?php

namespace Parroauth2\Client\Authentication;

use Parroauth2\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\StreamFactoryInterface;

use function http_build_query;

/**
 * Authenticate the client using request body fields, encoded in application/x-www-form-urlencoded
 *
 * The following fields will be added to the request body:
 * - client_id with the value of {@see ClientInterface::clientId()}
 * - client_secret with the value of {@see ClientInterface::secret()}
 *
 * @see https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1 For client authentication method
 */
final class RequestBodyClientAuthenticationMethod implements ClientAuthenticationMethodInterface
{
    public const NAME = 'client_secret_post';

    /**
     * @var StreamFactoryInterface
     */
    private $streamFactory;

    /**
     * @param StreamFactoryInterface $streamFactory
     */
    public function __construct(StreamFactoryInterface $streamFactory)
    {
        $this->streamFactory = $streamFactory;
    }

    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return self::NAME;
    }

    /**
     * {@inheritdoc}
     */
    public function apply(ClientInterface $client, RequestInterface $request): RequestInterface
    {
        $credentials = http_build_query([
            'client_id' => $client->clientId(),
            'client_secret' => $client->secret(),
        ]);
        $currentBody = (string) $request->getBody();

        if ($currentBody !== '') {
            $body = $currentBody . '&' . $credentials;
        } else {
            $body = $credentials;
        }

        return $request->withBody($this->streamFactory->createStream($body));
    }

    /**
     * {@inheritdoc}
     */
    public function withSigningAlgorithms(array $algorithms): ClientAuthenticationMethodInterface
    {
        return $this;
    }
}
