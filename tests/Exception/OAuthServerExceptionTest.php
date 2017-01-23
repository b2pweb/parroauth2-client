<?php

namespace Parroauth2\Client\Exception;

use Bdf\PHPUnit\TestCase;

/**
 * Class OAuthServerExceptionTest@group Parroauth2
 * @group Parroauth2/Exception
 * @group Parroauth2/Exception/OAuthServerException
 */
class OAuthServerExceptionTest extends TestCase
{
    /**
     * @dataProvider exceptionProvider
     */
    public function test_createFromResponse($response, $statusCode, $expectedClass)
    {
        $exception = OAuthServerException::createFromResponse($response, $statusCode);

        $this->assertInstanceOf($expectedClass, $exception);

        $this->assertEquals($response->error, $exception->errorType());
        $this->assertEquals($response->error_description, $exception->getMessage());
        $this->assertEquals($statusCode, $exception->getCode());

        if (isset($response->hint)) {
            $this->assertEquals($response->hint, $exception->hint());
        }
    }

    /**
     *
     */
    public function exceptionProvider()
    {
        return [
            [(object)['error' => 'access_denied',             'error_description' => 'Access denied'],                                            403, AccessDeniedException::class],
            [(object)['error' => 'invalid_client',            'error_description' => 'Error description', 'hint' => 'check client_id parameter'], 400, InvalidClientException::class],
            [(object)['error' => 'invalid_grant',             'error_description' => 'Error description', 'hint' => 'grant xxx not found'],       400, InvalidGrantException::class],
            [(object)['error' => 'invalid_request',           'error_description' => 'Error description', 'hint' => 'check redirect_uri'],        400, InvalidRequestException::class],
            [(object)['error' => 'invalid_scope',             'error_description' => 'Error description', 'hint' => 'scope `test` not found'],    400, InvalidScopeException::class],
            [(object)['error' => 'server_error',              'error_description' => 'Server error'],                                             500, ServerErrorException::class],
            [(object)['error' => 'temporarily_unavailable',   'error_description' => 'Temporarily unavailable'],                                  500, TemporarilyUnavailableException::class],
            [(object)['error' => 'unauthorized_client',       'error_description' => 'Error description'],                                        401, UnauthorizedClientException::class],
            [(object)['error' => 'unsupported_grant_type',    'error_description' => 'Error description'],                                        400, UnsupportedGrantTypeException::class],
            [(object)['error' => 'unsupported_response_type', 'error_description' => 'Unsupported response type'],                                400, UnsupportedResponseTypeException::class],
            [(object)['error' => 'undefined_error',           'error_description' => 'Non-standard OAuth error'],                                 400, OAuthServerException::class]
        ];
    }
}