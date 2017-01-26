<?php

namespace Parroauth2\Client\GrantTypes;

use Parroauth2\Client\Request;

/**
 * RefreshTokenGrantType
 */
class RefreshTokenGrantType implements GrantTypeInterface
{
    /**
     * @var string
     */
    protected $token;

    /**
     * @var string[]
     */
    protected $scopes;
    
    /**
     * RefreshGrantType constructor.
     * 
     * @param string $token
     * @param null|string[] $scopes
     */
    public function __construct($token, array $scopes = null)
    {
        $this->token = $token;
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
     */
    protected function toArray()
    {
        $data = [
            'grant_type'    => 'refresh_token',
            'refresh_token' => $this->token,
        ];

        if ($this->scopes !== null) {
            $data['scope'] = implode(' ', $this->scopes);
        }

        return $data;
    }
}