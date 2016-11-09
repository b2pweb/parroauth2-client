<?php

namespace Parroauth2\Client\GrantTypes;

use Parroauth2\Client\Request;

/**
 * Class ClientCredentialsGrant
 */
class ClientCredentialsGrant implements GrantTypeInterface
{
    /**
     * @var string[]
     */
    protected $scopes;

    /**
     * ClientCredentialsGrant constructor.
     * 
     * @param string[] $scopes
     */
    public function __construct(array $scopes = [])
    {
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
        $data = ['grant_type' => 'client_credentials'];

        if ($this->scopes) {
            $data['scope'] = implode(' ', $this->scopes);
        }

        return $data;
    }
}