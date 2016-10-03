<?php

namespace Parroauth2\Client\GrantTypes;

use Parroauth2\Client\Request;

/**
 * Class AuthorizationGrantType
 *
 * @package Parroauth2\Client\GrantTypes
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
     * AuthorizationGrantType constructor.
     *
     * @param string $code
     * @param string $redirectUri
     * @param string $clientId
     */
    public function __construct($code, $redirectUri = '', $clientId = '')
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
        $request->addParameters($this->toArray());
        
        return $this;
    }

    /**
     * @return array
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

        return $data;
    }
}