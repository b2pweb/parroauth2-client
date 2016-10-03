<?php

namespace Parroauth2\Client\Tests;

use Bdf\PHPUnit\TestCase;
use Parroauth2\Client\Introspection;
use Parroauth2\Client\Response;

/**
 * Class IntrospectionTest
 *
 * @group Parroauth2
 * @group Parroauth2/Client
 * @group Parroauth2/Client/Introspection
 */
class IntrospectionTest extends TestCase
{
    /**
     * 
     */
    public function testFromResponse_sets_active_depending_on_expireIn_property()
    {
        $expected = (new Introspection())
            ->setActive(false)
        ;
        
        $response = new Response([
            'exp' => 0,
        ]);

        $this->assertEquals($expected, Introspection::fromResponse($response));
    }
    
    /**
     * 
     */
    public function testFromResponse()
    {
        $time = time();
        
        $expected = (new Introspection())
            ->setActive(true)
            ->setScopes(['scope1', 'scope2'])
            ->setClientId('client_id')
            ->setUsername('username')
            ->setTokenType('bearer')
            ->setExpireIn($time + 3600)
            ->setIssuedAt($time - 3600)
            ->setNotBefore($time - 3600)
            ->setSubject('subject')
            ->setAudience('client_id')
            ->setIssuer('issuer')
            ->setJwtId('jwtId')
            ->setMetadata(['meta1' => 'data1', 'meta2' => 'data2'])
        ;
        
        $response = new Response([
            'active'     => $expected->isActive(),
            'scope'      => implode(' ', $expected->getScopes()),
            'client_id'  => $expected->getClientId(),
            'username'   => $expected->getUsername(),
            'token_type' => $expected->getTokenType(),
            'exp'        => $expected->getExpireIn(),
            'iat'        => $expected->getIssuedAt(),
            'nbf'        => $expected->getNotBefore(),
            'sub'        => $expected->getSubject(),
            'aud'        => $expected->getAudience(),
            'iss'        => $expected->getIssuer(),
            'jti'        => $expected->getJwtId(),
            'metadata'   => $expected->getMetadata(),
        ]);

        $this->assertEquals($expected, Introspection::fromResponse($response));
    }
}