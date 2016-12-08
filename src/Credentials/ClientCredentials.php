<?php

namespace Parroauth2\Client\Credentials;

use Parroauth2\Client\Request;

/**
 * ClientCredentials
 */
class ClientCredentials
{
    /**
     * @var string
     */
    protected $id;

    /**
     * @var string
     */
    protected $secret;

    /**
     * ClientCredentials constructor.
     *
     * @param string $id
     * @param string $secret
     */
    public function __construct($id, $secret)
    {
        $this->id = $id;
        $this->secret = $secret;
    }

    /**
     * @param string $id
     *
     * @return ClientCredentials
     */
    public function setId($id)
    {
        $this->id = $id;

        return $this;
    }

    /**
     * @return string
     */
    public function id()
    {
        return $this->id;
    }

    /**
     * @param string $secret
     *
     * @return ClientCredentials
     */
    public function setSecret($secret)
    {
        $this->secret = $secret;

        return $this;
    }

    /**
     * @return string
     */
    public function secret()
    {
        return $this->secret;
    }

    /**
     * Prepare the request
     *
     * @param Request $request
     */
    public function prepare(Request $request)
    {
        $request->addHeaders([
            'Authorization' => 'Basic '.base64_encode($this->id.':'.$this->secret)
        ]);
    }
}