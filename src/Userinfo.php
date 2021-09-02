<?php

namespace Parroauth2\Client;

use Parroauth2\Client\OpenID\EndPoint\Userinfo\UserinfoResponse;

/**
 * Userinfo
 *
 * @deprecated Use UserinfoResponse
 */
class Userinfo
{
    /**
     * @var string
     */
    private $subject;

    /**
     * @var array
     */
    private $info;

    /**
     * @param string $subject
     *
     * @return $this
     */
    public function setSubject($subject)
    {
        $this->subject = $subject;

        return $this;
    }

    /**
     * @return string
     */
    public function subject()
    {
        return $this->subject;
    }

    /**
     * @param array $info
     *
     * @return $this
     */
    public function setInfo(array $info)
    {
        $this->info = $info;

        return $this;
    }

    /**
     * Get the info from key
     *
     * Returns a key value is key is not null
     *
     * @param string|null $key
     * @param mixed $default
     *
     * @return mixed
     */
    public function info($key = null, $default = null)
    {
        if ($key === null) {
            return $this->info;
        }

        return isset($this->info[$key]) ? $this->info[$key] : $default;
    }

    /**
     * @param UserinfoResponse $response
     *
     * @return self
     *
     * @internal
     */
    public static function fromResponse(UserinfoResponse $response)
    {
        $userinfo = new self();

        $userinfo
            ->setSubject($response->subject())
            ->setInfo($response->claims())
        ;

        return $userinfo;
    }
}
