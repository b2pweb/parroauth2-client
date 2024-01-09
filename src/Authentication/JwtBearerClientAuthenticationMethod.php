<?php

namespace Parroauth2\Client\Authentication;

use B2pweb\Jwt\EncodingOptions;
use B2pweb\Jwt\JwtEncoder;
use Base64Url\Base64Url;
use InvalidArgumentException;
use Jose\Component\KeyManagement\JWKFactory;
use Parroauth2\Client\ClientInterface;
use Parroauth2\Client\Jwt\JWA;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\StreamFactoryInterface;

use function http_build_query;
use function random_bytes;
use function time;

/**
 * Client authentication method using JWT bearer
 *
 * The authentication will be done using a temporary JWT token passed in the request body, with the following fields:
 * - client_assertion_type with the value "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", indicating the use of JWT bearer
 * - client_assertion with the value of the JWT token
 *
 * The JWT will be signed using the client secret, and will contain the following claims:
 * - "iss" : The issuer. By default, will be the client id ({@see ClientInterface::clientId()}). Can be changed using the "jwt-bearer.issuer" option
 * - "sub" : The subject. Will always be the client id
 * - "aud" : The audience. By default, will be the target URI of the endpoint ({@see RequestInterface::getUri()}), without the query string and fragment. Can be changed using the "jwt-bearer.audience" option.
 * - "exp" : The expiration time. By default, will be the current time + 30 seconds. Can be changed using the "jwt-bearer.expiration" option.
 * - "iat" : The issued at time. Will be the current time.
 * - "nbf" : The not before. Will be the current time.
 * - "jti" : The JWT ID. Will be a random string of 24 bits encoded in base64 url safe, resulting in a 32 characters string.
 *
 * The JWT will be signed using "HS256" algorithm by default. Can be changed using the "jwt-bearer.algorithm" option.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7523 For the specification
 */
final class JwtBearerClientAuthenticationMethod implements ClientAuthenticationMethodInterface
{
    public const NAME = 'client_secret_jwt';

    public const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

    public const OPTION_ISSUER = 'jwt-bearer.issuer';
    public const OPTION_AUDIENCE = 'jwt-bearer.audience';
    public const OPTION_EXPIRATION = 'jwt-bearer.expiration';
    public const OPTION_ALGORITHM = 'jwt-bearer.algorithm';

    /**
     * @var StreamFactoryInterface
     */
    private $streamFactory;

    /**
     * @var JwtEncoder
     */
    private $encoder;

    /**
     * @param StreamFactoryInterface $streamFactory
     * @param JwtEncoder $encoder
     */
    public function __construct(StreamFactoryInterface $streamFactory, JwtEncoder $encoder)
    {
        $this->streamFactory = $streamFactory;
        $this->encoder = $encoder;
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
        $jwt = $this->createJwt($client, $request);
        $credentials = http_build_query([
            'client_assertion_type' => self::ASSERTION_TYPE,
            'client_assertion' => $jwt,
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
        $self = clone $this;
        $self->encoder = $this->encoder->supportedAlgorithms($algorithms);

        return $self;
    }

    private function createJwt(ClientInterface $client, RequestInterface $request): string
    {
        $secret = $client->secret();

        if (!$secret) {
            throw new InvalidArgumentException('The client secret is required to use the JWT bearer authentication method');
        }

        $issuer = $client->option(self::OPTION_ISSUER, $client->clientId());
        $subject = $client->clientId();
        $audience = $client->option(self::OPTION_AUDIENCE, (string) $request->getUri()->withQuery('')->withFragment(''));
        $iat = $nbf = time();
        $expiration = $iat + $client->option(self::OPTION_EXPIRATION, 30);
        $jti = Base64Url::encode(random_bytes(24));
        $algorithm = $client->option(self::OPTION_ALGORITHM, $this->encoder->jwa()->algorithmsByType(JWA::TYPE_HMAC)[0] ?? 'HS256');

        $claims = [
            'iss' => $issuer,
            'sub' => $subject,
            'aud' => $audience,
            'exp' => $expiration,
            'iat' => $iat,
            'nbf' => $nbf,
            'jti' => $jti,
        ];

        return $this->encoder->encode(
            $claims,
            EncodingOptions::fromKey(
                JWKFactory::createFromSecret($secret, ['use' => 'sig', 'alg' => $algorithm])
            )
        );
    }
}
