<?php

namespace Parroauth2\Client\GrantTypes;

use Parroauth2\Client\Request;

/**
 * Class RefreshGrantType
 */
class RefreshGrantType implements GrantTypeInterface
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
     * @param string[] $scopes
     */
    public function __construct($token, array $scopes = [])
    {
        $this->token = $token;
        $this->scopes = $scopes;
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
            'grant_type' => 'refresh_token',
            'token'      => $this->token,
        ];

        if ($this->scopes) {
            $data['scope'] = implode(' ', $this->scopes);
        }

        return $data;
    }
}