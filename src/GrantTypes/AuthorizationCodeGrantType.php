<?php

namespace Parroauth2\Client\GrantTypes;

use Parroauth2\Client\Request;

/**
 * AuthorizationCodeGrantType
 */
class AuthorizationCodeGrantType implements GrantTypeInterface
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
     * AuthorizationGrantType constructor.
     *
     * @param string $code
     * @param null|string $redirectUri
     * @param null|string $clientId
     */
    public function __construct($code, $redirectUri = null, $clientId = null)
    {
        $this->code = $code;
        $this->redirectUri = $redirectUri;
        $this->clientId = $clientId;
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

        if ($this->redirectUri !== null) {
            $data['redirect_uri'] = $this->redirectUri;
        }

        if ($this->clientId !== null) {
            $data['client_id'] = $this->clientId;
        }

        return $data;
    }
}