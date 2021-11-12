<?php

namespace Parroauth2\Client\Extension;

use Parroauth2\Client\EndPoint\Introspection\IntrospectionResponse;
use Parroauth2\Client\Exception\AccessDeniedException;
use Parroauth2\Client\Tests\FunctionalTestCase;

/**
 *
 */
class RequiredScopeValidatorTest extends FunctionalTestCase
{
    /**
     */
    private $extension;


    /**
     *
     */
    public function test_validate_all_scopes()
    {
        $this->extension = new RequiredScopeValidator(['email', 'profile']);
        $response = new IntrospectionResponse(['scope' => 'email profile phone']);

        $this->assertNull($this->extension->validate($response));
    }

    /**
     *
     */
    public function test_validate_missing_mandatory_claims()
    {
        $this->expectException(AccessDeniedException::class);

        $this->extension = new RequiredScopeValidator(['email']);
        $response = new IntrospectionResponse(['scope' => 'profile phone']);

        $this->extension->validate($response);
    }

    /**
     *
     */
    public function test_validate_with_no_scope()
    {
        $this->expectException(AccessDeniedException::class);

        $this->extension = new RequiredScopeValidator(['email']);
        $response = new IntrospectionResponse(['scope' => '']);

        $this->extension->validate($response);
    }
}
