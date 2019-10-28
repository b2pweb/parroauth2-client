<?php

namespace Parroauth2\Client\OpenID\EndPoint;

use Base64Url\Base64Url;
use Parroauth2\Client\EndPoint\Authorization\AuthorizationEndPoint as BaseAuthorizationEndPoint;

/**
 * Authorization endpoint for OpenID Connect provider
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint
 */
class AuthorizationEndPoint extends BaseAuthorizationEndPoint
{
    /**
     * {@inheritdoc}
     */
    public function scope(array $scopes): BaseAuthorizationEndPoint
    {
        if (!in_array('openid', $scopes)) {
            array_unshift($scopes, 'openid');
        }

        return BaseAuthorizationEndPoint::scope($scopes);
    }

    /**
     * {@inheritdoc}
     */
    public function uri(): string
    {
        if (isset($this->parameters()['scope'])) {
            return parent::uri();
        }

        // Add the scope parameter if not yet set
        return $this->set('scope', 'openid')->uri();
    }

    /**
     * Set the nonce
     *
     * @param string|null $nonce The nonce, or null to generate it
     *
     * @return self
     */
    public function nonce(?string $nonce = null): self
    {
        if ($nonce === null) {
            $nonce = Base64Url::encode(random_bytes(32));
        }

        return $this->set('nonce', $nonce);
    }
}
