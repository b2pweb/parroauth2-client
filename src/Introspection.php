<?php

namespace Parroauth2\Client;

/**
 * Introspection
 */
class Introspection
{
    /**
     * @var bool
     */
    protected $active;

    /**
     * @var string[]
     */
    protected $scopes = [];

    /**
     * @var string
     */
    protected $clientId;

    /**
     * @var string
     */
    protected $username;

    /**
     * @var string
     */
    protected $tokenType;

    /**
     * @var int
     */
    protected $expireIn;

    /**
     * @var int
     */
    protected $issuedAt;

    /**
     * @var int
     */
    protected $notBefore;

    /**
     * @var string
     */
    protected $subject;

    /**
     * @var string
     */
    protected $audience;

    /**
     * @var string
     */
    protected $issuer;

    /**
     * @var string
     */
    protected $jwtId;

    /**
     * @var array
     */
    protected $metadata;

    /**
     * @param boolean $active
     *
     * @return $this
     */
    public function setActive($active)
    {
        $this->active = $active;

        return $this;
    }

    /**
     * @return boolean
     */
    public function isActive()
    {
        return $this->active;
    }

    /**
     * @param string[] $scopes
     *
     * @return $this
     */
    public function setScopes(array $scopes)
    {
        $this->scopes = $scopes;

        return $this;
    }

    /**
     * @return string[]
     */
    public function scopes()
    {
        return $this->scopes;
    }

    /**
     * @param $scope
     *
     * @return bool
     */
    public function hasScope($scope)
    {
        return in_array($scope, $this->scopes);
    }

    /**
     * @param string $clientId
     *
     * @return $this
     */
    public function setClientId($clientId)
    {
        $this->clientId = $clientId;

        return $this;
    }

    /**
     * @return string
     */
    public function clientId()
    {
        return $this->clientId;
    }

    /**
     * @param string $username
     *
     * @return $this
     */
    public function setUsername($username)
    {
        $this->username = $username;

        return $this;
    }

    /**
     * @return string
     */
    public function username()
    {
        return $this->username;
    }

    /**
     * @param string $tokenType
     *
     * @return $this
     */
    public function setTokenType($tokenType)
    {
        $this->tokenType = $tokenType;

        return $this;
    }

    /**
     * @return string
     */
    public function tokenType()
    {
        return $this->tokenType;
    }

    /**
     * @param int $expireIn
     *
     * @return $this
     */
    public function setExpireIn($expireIn)
    {
        $this->expireIn = $expireIn;

        return $this;
    }

    /**
     * @return int
     */
    public function expireIn()
    {
        return $this->expireIn;
    }

    /**
     * @param int $issuedAt
     *
     * @return $this
     */
    public function setIssuedAt($issuedAt)
    {
        $this->issuedAt = $issuedAt;

        return $this;
    }

    /**
     * @return int
     */
    public function issuedAt()
    {
        return $this->issuedAt;
    }

    /**
     * @param int $notBefore
     *
     * @return $this
     */
    public function setNotBefore($notBefore)
    {
        $this->notBefore = $notBefore;

        return $this;
    }

    /**
     * @return int
     */
    public function notBefore()
    {
        return $this->notBefore;
    }

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
     * @param string $audience
     *
     * @return $this
     */
    public function setAudience($audience)
    {
        $this->audience = $audience;

        return $this;
    }

    /**
     * @return string
     */
    public function audience()
    {
        return $this->audience;
    }

    /**
     * @param string $issuer
     *
     * @return $this
     */
    public function setIssuer($issuer)
    {
        $this->issuer = $issuer;

        return $this;
    }

    /**
     * @return string
     */
    public function issuer()
    {
        return $this->issuer;
    }

    /**
     * @param string $jwtId
     *
     * @return $this
     */
    public function setJwtId($jwtId)
    {
        $this->jwtId = $jwtId;

        return $this;
    }

    /**
     * @return string
     */
    public function jwtId()
    {
        return $this->jwtId;
    }

    /**
     * @param $metadata
     *
     * @return $this
     */
    public function setMetadata($metadata)
    {
        $this->metadata = $metadata;

        return $this;
    }

    /**
     * Get the metadata from key
     *
     * Returns a key value is key is not null
     *
     * @param string|null $key
     * @param mixed $default
     *
     * @return mixed
     */
    public function metadata($key = null, $default = null)
    {
        if ($key === null) {
            return $this->metadata;
        }

        return isset($this->metadata[$key]) ? $this->metadata[$key] : $default;
    }

    /**
     * @param Response $response
     * 
     * @return self
     */
    static public function fromResponse(Response $response)
    {
        $introspection = (new self())
            ->setActive($response->getBodyItem('active', false))
        ;

        if (!$introspection->isActive()) {
            return $introspection;
        }

        if ($response->hasBodyItem('scope')) {
            $introspection->setScopes(explode(' ', $response->getBodyItem('scope')));
        }

        $introspection
            ->setClientId($response->getBodyItem('client_id'))
            ->setUsername($response->getBodyItem('username'))
            ->setTokenType($response->getBodyItem('token_type'))
            ->setExpireIn($response->getBodyItem('exp'))
            ->setIssuedAt($response->getBodyItem('iat'))
            ->setNotBefore($response->getBodyItem('nbf'))
            ->setSubject($response->getBodyItem('sub'))
            ->setAudience($response->getBodyItem('aud'))
            ->setIssuer($response->getBodyItem('iss'))
            ->setJwtId($response->getBodyItem('jti'))
            ->setMetadata((array)$response->getBodyItem('metadata', []))
        ;

        return $introspection;
    }
}