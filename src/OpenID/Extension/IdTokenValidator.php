<?php

namespace Parroauth2\Client\OpenID\Extension;

use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\InvalidClaimException;
use Jose\Component\Checker\IssuedAtChecker;
use Parroauth2\Client\EndPoint\Authorization\AuthorizationEndPoint;
use Parroauth2\Client\EndPoint\EndPointTransformerTrait;
use Parroauth2\Client\EndPoint\Token\TokenEndPoint;
use Parroauth2\Client\EndPoint\Token\TokenResponse;
use Parroauth2\Client\Extension\AbstractEndPointTransformerExtension;
use Parroauth2\Client\OpenID\EndPoint\AuthorizationEndPoint as OpenIdAuthorizationEndPoint;
use Parroauth2\Client\OpenID\EndPoint\Token\TokenResponse as OpenIdTokenResponse;
use Parroauth2\Client\OpenID\IdToken\AccessTokenHash;

/**
 * Perform validation on the returned ID Token
 *
 * Client options :
 * - id_token_required (bool) Does the ID Token is required ? Default to false
 * - id_token_max_iat_interval (int) The max time interval (in seconds) for the ID Token issued at time. Default to 30
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
 */
final class IdTokenValidator extends AbstractEndPointTransformerExtension
{
    use EndPointTransformerTrait;

    /**
     * @var AccessTokenHash
     */
    private $accessTokenHash;


    /**
     * IdTokenValidator constructor.
     *
     * @param AccessTokenHash|null $accessTokenHash
     */
    public function __construct(?AccessTokenHash $accessTokenHash = null)
    {
        $this->accessTokenHash = $accessTokenHash ?: new AccessTokenHash();
    }

    /**
     * {@inheritdoc}
     */
    public function onAuthorization(AuthorizationEndPoint $endPoint): AuthorizationEndPoint
    {
        if ($endPoint instanceof OpenIdAuthorizationEndPoint) {
            $endPoint = $endPoint->nonce();

            $this->client()->storage()->store('nonce', $endPoint->get('nonce'));
        }

        return $endPoint;
    }

    /**
     * {@inheritdoc}
     */
    public function onToken(TokenEndPoint $endPoint): TokenEndPoint
    {
        return $endPoint->onResponse([$this, 'validate']);
    }

    /**
     * Validate the ID Token claims
     *
     * @param TokenResponse $response
     *
     * @throws \Jose\Component\Checker\InvalidClaimException
     * @throws \Jose\Component\Checker\MissingMandatoryClaimException
     * @throws \InvalidArgumentException
     *
     * @internal
     */
    public function validate(TokenResponse $response): void
    {
        if (!$response instanceof OpenIdTokenResponse || !$response->idToken()) {
            if ($this->client()->clientConfig()->option('id_token_required', false)) {
                throw new \InvalidArgumentException('ID Token is required on the token response');
            }

            return;
        }

        $idToken = $response->idToken();

        $checker = new ClaimCheckerManager([
            new IssuedAtChecker(),
            new ExpirationTimeChecker(),
            new AudienceChecker($this->client()->clientId()),
        ]);

        $checker->check($idToken->claims(), ['iss', 'sub', 'aud', 'exp', 'iat']);

        $client = $this->client();

        if ($idToken->issuer() !== $client->provider()->issuer()) {
            throw new InvalidClaimException('The issuer is invalid', 'iss', $idToken->issuer());
        }

        if (is_array($idToken->audience()) && count($idToken->audience()) > 0 && !$idToken->authorizedParty()) {
            throw new InvalidClaimException(
                'The authorized party is required when multiple audience are provided',
                'azp',
                ''
            );
        }

        if ($idToken->authorizedParty() && $idToken->authorizedParty() !== $client->clientId()) {
            throw new InvalidClaimException(
                'The authorized party must be identically to the current client id',
                'azp',
                $idToken->authorizedParty()
            );
        }

        if (time() - $idToken->issuedAt() > $client->clientConfig()->option('id_token_max_iat_interval', 30)) {
            throw new InvalidClaimException('The ID Token is issued too far in the past', 'iat', $idToken->issuedAt());
        }

        if (($nonce = $client->storage()->remove('nonce')) && !$idToken->check('nonce', $nonce)) {
            throw new InvalidClaimException('Invalid nonce', 'nonce', $idToken->nonce());
        }

        if (!$this->accessTokenHash->check($idToken, $response->accessToken())) {
            throw new InvalidClaimException(
                'Access token hash do not corresponds',
                'at_hash',
                $idToken->accessTokenHash()
            );
        }
    }
}
