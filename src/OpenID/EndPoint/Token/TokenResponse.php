<?php

namespace Parroauth2\Client\OpenID\EndPoint\Token;

use Parroauth2\Client\EndPoint\Token\TokenResponse as BaseTokenResponse;
use Parroauth2\Client\OpenID\IdToken\IdToken;

/**
 * OpenID Connect response for the token endpoint
 * Add the id_token field
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
 *
 * @psalm-immutable
 */
class TokenResponse extends BaseTokenResponse
{
    /**
     * @var IdToken|null
     */
    private $idToken;


    /**
     * TokenResponse constructor.
     *
     * @param array<string, mixed> $response
     * @param IdToken|null $idToken
     */
    public function __construct(array $response, ?IdToken $idToken)
    {
        parent::__construct($response);

        $this->idToken = $idToken;
    }

    /**
     * Get the ID Token on the response
     *
     * @return IdToken|null
     */
    public function idToken(): ?IdToken
    {
        return $this->idToken;
    }
}
