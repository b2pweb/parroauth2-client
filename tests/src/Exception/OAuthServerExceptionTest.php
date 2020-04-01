<?php

namespace Parroauth2\Client\Exception;

use PHPUnit\Framework\TestCase;

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
    public function test_createFromResponse($type, $message, $hint, $statusCode, $expectedClass)
    {
        $exception = OAuthServerException::create($type, $message, $hint);

        $this->assertInstanceOf($expectedClass, $exception);

        $this->assertEquals($type, $exception->getErrorType());
        $this->assertEquals($message, $exception->getMessage());
        $this->assertEquals($statusCode, $exception->getStatusCode());
        $this->assertEquals($hint, $exception->getHint());
    }

    /**
     *
     */
    public function exceptionProvider()
    {
        return [
            ['access_denied',             'Access denied',               null,                        403, AccessDeniedException::class],
            ['invalid_client',            'Error description',           'check client_id parameter', 401, InvalidClientException::class],
            ['invalid_grant',             'Error description',           'grant xxx not found',       400, InvalidGrantException::class],
            ['invalid_request',           'Error description',           'check redirect_uri',        400, InvalidRequestException::class],
            ['invalid_scope',             'Error description',           'scope `test` not found',    400, InvalidScopeException::class],
            ['server_error',              'Server error',                null,                        500, ServerErrorException::class],
            ['temporarily_unavailable',   'Temporarily unavailable',     null,                        503, TemporarilyUnavailableException::class],
            ['unauthorized_client',       'Error description',           null,                        400, UnauthorizedClientException::class],
            ['unsupported_grant_type',    'Error description',           null,                        400, UnsupportedGrantTypeException::class],
            ['unsupported_response_type', 'Unsupported response type',   null,                        400, UnsupportedResponseTypeException::class],
            ['undefined_error',           'Non-standard OAuth error',    null,                        400, OAuthServerException::class]
        ];
    }
}