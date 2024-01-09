<?php

namespace Parroauth2\Client\Authentication;

use Parroauth2\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;

use function base64_encode;

/**
 * Authenticate the client using "Authorization: Basic" header
 * The client id and secret are encoded in base64 in the header value
 *
 * @see https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1 For client authentication method
 * @see https://www.rfc-editor.org/rfc/rfc7617 For basic authentication scheme
 */
final class BasicClientAuthenticationMethod implements ClientAuthenticationMethodInterface
{
    public const NAME = 'client_secret_basic';

    private const HEADER = 'Authorization';
    private const SCHEME = 'Basic';

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
        $credentials = base64_encode($client->clientId() . ':' . $client->secret());

        return $request->withHeader(self::HEADER, self::SCHEME . ' ' . $credentials);
    }

    /**
     * {@inheritdoc}
     */
    public function withSigningAlgorithms(array $algorithms): ClientAuthenticationMethodInterface
    {
        return $this;
    }
}
