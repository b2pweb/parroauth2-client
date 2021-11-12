<?php

namespace Parroauth2\Client\Extension;

use Parroauth2\Client\EndPoint\EndPointTransformerTrait;
use Parroauth2\Client\EndPoint\Introspection\IntrospectionEndPoint;
use Parroauth2\Client\EndPoint\Introspection\IntrospectionResponse;
use Parroauth2\Client\Exception\AccessDeniedException;

/**
 * Perform validation on the returned introspection response to check the associated scopes.
 * All scope of this validator have to be present in the introspection scopes.
 */
final class RequiredScopeValidator extends AbstractEndPointTransformerExtension
{
    use EndPointTransformerTrait;

    /**
     * @var string[]
     */
    private $scopes;


    /**
     * @param string[] $scopes
     */
    public function __construct(array $scopes)
    {
        $this->scopes = $scopes;
    }

    /**
     * {@inheritdoc}
     */
    public function onIntrospection(IntrospectionEndPoint $endPoint): IntrospectionEndPoint
    {
        return $endPoint->onResponse([$this, 'validate']);
    }

    /**
     * Validate the all scopes are in the introspection response
     *
     * @param IntrospectionResponse $response
     *
     * @internal
     */
    public function validate(IntrospectionResponse $response): void
    {
        if (empty($scopes = $response->scopes())) {
            throw new AccessDeniedException("The introspection response has no scopes.");
        }

        foreach ($this->scopes as $scope) {
            if (!in_array($scope, $scopes)) {
                throw new AccessDeniedException(
                    "The scope '$scope' is not present in introspection response. Available scopes are " . implode(', ', $scopes)
                );
            }
        }
    }
}
