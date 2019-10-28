<?php

namespace Parroauth2\Client\OpenID\Extension;

use Jose\Component\Checker\InvalidClaimException;
use Jose\Component\Checker\MissingMandatoryClaimException;
use Parroauth2\Client\Client;
use Parroauth2\Client\ClientConfig;
use Parroauth2\Client\OpenID\EndPoint\Token\TokenResponse;
use Parroauth2\Client\OpenID\IdToken\AccessTokenHash;
use Parroauth2\Client\OpenID\IdToken\IdToken;
use Parroauth2\Client\Tests\FunctionalTestCase;

/**
 * Class IdTokenValidatorTest
 */
class IdTokenValidatorTest extends FunctionalTestCase
{
    /**
     * @var Client
     */
    private $client;

    /**
     * @var IdTokenValidator
     */
    private $extension;

    protected function setUp(): void
    {
        parent::setUp();

        $this->client = $this->client(
            (new ClientConfig('test'))
                ->setSecret('my-secret')
                ->setScopes(['email', 'name'])
                ->enableOpenId(true)
        );
        $this->extension = new IdTokenValidator();
        $this->client->register($this->extension);
        $this->dataSet
            ->pushClient('test', 'my-secret', 'http://client.example.com')
            ->pushScopes(['email', 'name'])
        ;
    }

    /**
     *
     */
    public function test_should_add_nonce_on_authorization_endpoint()
    {
        $authorization = $this->client->endPoints()->authorization();

        $this->assertNotEmpty($authorization->get('nonce'));
        $this->assertSame($authorization->get('nonce'), $this->session->retrieve('nonce'));
    }

    /**
     *
     */
    public function test_should_validate_token_response_success()
    {
        $response = $this->client->endPoints()->token()
            ->code($this->code())
            ->call()
        ;

        $this->assertInstanceOf(TokenResponse::class, $response);
        $this->assertInstanceOf(IdToken::class, $response->idToken());
    }

    /**
     *
     */
    public function test_should_validate_token_response_invalid_nonce()
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('Invalid nonce');

        $code = $this->code();
        $this->session->store('nonce', 'invalid');

        $this->client->endPoints()->token()
            ->code($code)
            ->call()
        ;
    }

    /**
     *
     */
    public function test_validate_missing_mandatory_claims()
    {
        $this->expectException(MissingMandatoryClaimException::class);

        $idToken = new IdToken('', [], ['alg' => 'RS256']);
        $response = new TokenResponse([], $idToken);

        $this->extension->validate($response);
    }

    /**
     *
     */
    public function test_validate_invalid_issuer()
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('The issuer is invalid');

        $idToken = new IdToken('', [
            'iss' => 'invalid',
            'sub' => '1234',
            'aud' => 'test',
            'exp' => time() + 1000,
            'iat' => time(),
        ], ['alg' => 'RS256']);
        $response = new TokenResponse([], $idToken);

        $this->extension->validate($response);
    }

    /**
     *
     */
    public function test_validate_expired_token()
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('The JWT has expired.');

        $idToken = new IdToken('', [
            'iss' => 'http://localhost:5000',
            'sub' => '1234',
            'aud' => 'test',
            'exp' => time() - 1000,
            'iat' => time(),
        ], ['alg' => 'RS256']);
        $response = new TokenResponse([], $idToken);

        $this->extension->validate($response);
    }

    /**
     *
     */
    public function test_validate_invalid_audience()
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('Bad audience.');

        $idToken = new IdToken('', [
            'iss' => 'http://localhost:5000',
            'sub' => '1234',
            'aud' => 'invalid',
            'exp' => time() + 1000,
            'iat' => time(),
        ], ['alg' => 'RS256']);
        $response = new TokenResponse([], $idToken);

        $this->extension->validate($response);
    }

    /**
     *
     */
    public function test_validate_multiple_audience_without_azp()
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('The authorized party is required when multiple audience are provided');

        $idToken = new IdToken('', [
            'iss' => 'http://localhost:5000',
            'sub' => '1234',
            'aud' => ['test', 'other'],
            'exp' => time() + 1000,
            'iat' => time(),
        ], ['alg' => 'RS256']);
        $response = new TokenResponse([], $idToken);

        $this->extension->validate($response);
    }

    /**
     *
     */
    public function test_validate_invalid_azp()
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('The authorized party must be identically to the current client id');

        $idToken = new IdToken('', [
            'iss' => 'http://localhost:5000',
            'sub' => '1234',
            'aud' => 'test',
            'azp' => 'invalid',
            'exp' => time() + 1000,
            'iat' => time(),
        ], ['alg' => 'RS256']);
        $response = new TokenResponse([], $idToken);

        $this->extension->validate($response);
    }

    /**
     *
     */
    public function test_validate_issued_at_too_early()
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('The ID Token is issued too far in the past');

        $idToken = new IdToken('', [
            'iss' => 'http://localhost:5000',
            'sub' => '1234',
            'aud' => 'test',
            'exp' => time() + 1000,
            'iat' => time() - 1000,
        ], ['alg' => 'RS256']);
        $response = new TokenResponse([], $idToken);

        $this->extension->validate($response);
    }

    /**
     *
     */
    public function test_validate_invalid_nonce()
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('Invalid nonce');

        $idToken = new IdToken('', [
            'iss' => 'http://localhost:5000',
            'sub' => '1234',
            'aud' => 'test',
            'exp' => time() + 1000,
            'iat' => time(),
            'nonce' => 'invalid',
        ], ['alg' => 'RS256']);
        $response = new TokenResponse([], $idToken);

        $this->session->store('nonce', 'my-nonce');

        $this->extension->validate($response);
    }

    /**
     *
     */
    public function test_validate_access_token_hash()
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('Access token hash do not corresponds');

        $idToken = new IdToken('', [
            'iss' => 'http://localhost:5000',
            'sub' => '1234',
            'aud' => 'test',
            'exp' => time() + 1000,
            'iat' => time(),
            'nonce' => 'my-nonce',
            'at_hash' => 'invalid'
        ], ['alg' => 'RS256']);
        $response = new TokenResponse([
            'access_token' => 'my access token'
        ], $idToken);

        $this->session->store('nonce', 'my-nonce');

        $this->extension->validate($response);
    }

    /**
     *
     */
    public function test_validate_success()
    {
        $idToken = new IdToken('', [
            'iss' => 'http://localhost:5000',
            'sub' => '1234',
            'aud' => 'test',
            'exp' => time() + 1000,
            'iat' => time(),
            'nonce' => 'my-nonce',
            'at_hash' => (new AccessTokenHash())->compute('my access token', 'RS256')
        ], ['alg' => 'RS256']);
        $response = new TokenResponse([
            'access_token' => 'my access token'
        ], $idToken);

        $this->session->store('nonce', 'my-nonce');

        // No throws
        $this->assertNull($this->extension->validate($response));
    }

    /**
     *
     */
    public function test_validate_no_id_token_issued()
    {
        $response = new TokenResponse([], null);

        // No throws
        $this->assertNull($this->extension->validate($response));
    }

    /**
     *
     */
    public function test_validate_no_id_token_issued_but_required()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('ID Token is required on the token response');

        $this->client->clientConfig()->setOption('id_token_required', true);
        $response = new TokenResponse([], null);

        $this->extension->validate($response);
    }

    private function code(): string
    {
        $location = $this->httpClient->get($this->client->endPoints()->authorization()->code()->uri())->getHeaderLine('Location');
        parse_str(explode('?', $location)[1], $parameters);

        return $parameters['code'];
    }
}
