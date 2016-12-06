<?php

namespace Parroauth2\Client\GrantTypes;

use Parroauth2\Client\Request;

/**
 * Class PasswordGrantType
 */
class PasswordGrantType implements GrantTypeInterface
{
    /**
     * @var string
     */
    protected $username;

    /**
     * @var string
     */
    protected $password;

    /**
     * @var string[]
     */
    protected $scopes;

    /**
     * PasswordGrantType constructor.
     * 
     * @param string $username
     * @param string $password
     * @param string[] $scopes
     */
    public function __construct($username, $password, array $scopes = [])
    {
        $this->username = $username;
        $this->password = $password;
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
            'grant_type' => 'password',
            'username'   => $this->username,
            'password'   => $this->password,
        ];

        if ($this->scopes) {
            $data['scope'] = implode(' ', $this->scopes);
        }

        return $data;
    }
}