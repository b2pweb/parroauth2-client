<?php

namespace Parroauth2\Client\GrantTypes;

use Parroauth2\Client\Request;

/**
 * AuthorizationGrantType
 */
class AuthorizationGrantType implements GrantTypeInterface
{
    /**
     * @var string
     */
    protected $code;

    /**
     * @var string
     */
    protected $redirectUri;

    /**
     * @var string
     */
    protected $clientId;

    /**
     * @var string[]
     */
    protected $scopes;

    /**
     * AuthorizationGrantType constructor.
     *
     * @param string $code
     * @param string $redirectUri
     * @param string $clientId
     * @param string[] $scopes
     */
    public function __construct($code, $redirectUri, $clientId, array $scopes = [])
    {
        $this->code = $code;
        $this->redirectUri = $redirectUri;
        $this->clientId = $clientId;
        $this->scopes = $scopes;
    }

    /**
     * {@inheritdoc}
     */
    public function acquaint(Request $request)
    {
        $request->addAttributes($this->toArray());
        
        return $this;
    }

    /**
     * @return array
     *
     * @todo We should not add client_id if Oauth client has credentials
     */
    protected function toArray()
    {
        $data = [
            'grant_type' => 'authorization_code',
            'code'       => $this->code,
        ];

        if ($this->redirectUri) {
            $data['redirect_uri'] = $this->redirectUri;
        }

        if ($this->clientId) {
            $data['client_id'] = $this->clientId;
        }

        if ($this->scopes) {
            $data['scope'] = implode(' ', $this->scopes);
        }

        return $data;
    }
}