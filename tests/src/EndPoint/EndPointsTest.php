<?php

namespace Parroauth2\Client\EndPoint;

use Parroauth2\Client\Authentication\BasicClientAuthenticationMethod;
use Parroauth2\Client\Authentication\JwtBearerClientAuthenticationMethod;
use Parroauth2\Client\Authentication\RequestBodyClientAuthenticationMethod;
use Parroauth2\Client\Client;
use Parroauth2\Client\ClientConfig;
use Parroauth2\Client\EndPoint\Authorization\AuthorizationEndPoint;
use Parroauth2\Client\EndPoint\Introspection\IntrospectionEndPoint;
use Parroauth2\Client\EndPoint\Token\RevocationEndPoint;
use Parroauth2\Client\EndPoint\Token\TokenEndPoint;
use Parroauth2\Client\Extension\Pkce;
use Parroauth2\Client\OpenID\EndPoint\EndSessionEndPoint;
use Parroauth2\Client\OpenID\EndPoint\Userinfo\UserinfoEndPoint;
use Parroauth2\Client\Tests\UnitTestCase;

/**
 * Class EndPointsTest
 */
class EndPointsTest extends UnitTestCase
{
    /**
     * @var EndPoints
     */
    private $endPoints;

    protected function setUp(): void
    {
        parent::setUp();

        $this->endPoints = new EndPoints($this->provider());
    }

    /**
     *
     */
    public function test_get_not_implemented()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The endpoint "not_implemented" is not implemented');

        $this->endPoints->get('not_implemented');
    }

    /**
     *
     */
    public function test_get_success()
    {
        $endpoint = new TokenEndPoint($this->createMock(Client::class));

        $this->endPoints->add($endpoint);
        $this->assertSame($endpoint, $this->endPoints->get('token'));
    }

    /**
     *
     */
    public function test_get_with_extensions()
    {
        $client = $this->provider()->client((new ClientConfig('test')));
        $endpoint = new AuthorizationEndPoint($client);

        $this->endPoints->add($endpoint);
        $client->register($extension = new Pkce());
        $this->endPoints->register($extension);

        $return = $this->endPoints->get('authorization');

        $this->assertNotSame($endpoint, $return);
        $this->assertNotEmpty($return->get('code_challenge'));
    }

    /**
     *
     */
    public function test_uri()
    {
        $endPoint = $this->createMock(EndPointInterface::class);
        $endPoint->expects($this->any())->method('name')->willReturn('token');
        $endPoint->expects($this->any())->method('parameters')->willReturn(['foo' => 'bar']);

        $this->assertEquals('http://op.example.com/token?foo=bar', $this->endPoints->uri($endPoint));
    }

    /**
     *
     */
    public function test_request_GET()
    {
        $endPoint = $this->createMock(EndPointInterface::class);
        $endPoint->expects($this->any())->method('name')->willReturn('token');
        $endPoint->expects($this->any())->method('parameters')->willReturn(['foo' => 'bar']);

        $request = $this->endPoints->request('GET', $endPoint);

        $this->assertEquals('http://op.example.com/token?foo=bar', $request->getUri());
        $this->assertEquals('GET', $request->getMethod());
        $this->assertFalse($request->hasHeader('Content-Type'));
    }

    /**
     *
     */
    public function test_request_POST()
    {
        $endPoint = $this->createMock(EndPointInterface::class);
        $endPoint->expects($this->any())->method('name')->willReturn('token');
        $endPoint->expects($this->any())->method('parameters')->willReturn(['foo' => 'bar']);

        $request = $this->endPoints->request('POST', $endPoint);

        $this->assertEquals('http://op.example.com/token', $request->getUri());
        $this->assertEquals('foo=bar', $request->getBody());
        $this->assertEquals('POST', $request->getMethod());
        $this->assertEquals('application/x-www-form-urlencoded', $request->getHeaderLine('Content-Type'));
    }

    /**
     *
     */
    public function test_request_POST_empty_body_should_not_set_content_type_header()
    {
        $endPoint = $this->createMock(EndPointInterface::class);
        $endPoint->expects($this->any())->method('name')->willReturn('token');
        $endPoint->expects($this->any())->method('parameters')->willReturn([]);

        $request = $this->endPoints->request('POST', $endPoint);

        $this->assertEquals('http://op.example.com/token', $request->getUri());
        $this->assertEquals('POST', $request->getMethod());
        $this->assertFalse($request->hasHeader('Content-Type'));
    }

    /**
     *
     */
    public function test_authorization()
    {
        $client = $this->provider()->client((new ClientConfig('test')));
        $endpoint = new AuthorizationEndPoint($client);

        $this->endPoints->add($endpoint);

        $this->assertSame($endpoint, $this->endPoints->authorization());
    }

    /**
     *
     */
    public function test_token()
    {
        $client = $this->provider()->client((new ClientConfig('test')));
        $endpoint = new TokenEndPoint($client);

        $this->endPoints->add($endpoint);

        $this->assertSame($endpoint, $this->endPoints->token());
    }

    /**
     *
     */
    public function test_revocation()
    {
        $client = $this->provider()->client((new ClientConfig('test')));
        $endpoint = new RevocationEndPoint($client);

        $this->endPoints->add($endpoint);

        $this->assertSame($endpoint, $this->endPoints->revocation());
    }

    /**
     *
     */
    public function test_introspection()
    {
        $client = $this->provider()->client((new ClientConfig('test')));
        $endpoint = new IntrospectionEndPoint($client);

        $this->endPoints->add($endpoint);

        $this->assertSame($endpoint, $this->endPoints->introspection());
    }

    /**
     *
     */
    public function test_userinfo()
    {
        $client = $this->provider()->client((new ClientConfig('test')));
        $endpoint = new UserinfoEndPoint($client);

        $this->endPoints->add($endpoint);

        $this->assertSame($endpoint, $this->endPoints->userinfo());
    }

    /**
     *
     */
    public function test_endSession()
    {
        $client = $this->provider()->client((new ClientConfig('test')));
        $endpoint = new EndSessionEndPoint($client);

        $this->endPoints->add($endpoint);

        $this->assertSame($endpoint, $this->endPoints->endSession());
    }

    public function test_authenticationMethod_without_metadata()
    {
        $endPoints = $this->provider()->client((new ClientConfig('test')))->endPoints();

        $this->assertInstanceOf(BasicClientAuthenticationMethod::class, $endPoints->authenticationMethod('token'));
    }

    public function test_authenticationMethod_without_metadata_with_preferred_method()
    {
        $endPoints = $this->provider()->client((new ClientConfig('test')))->endPoints();

        $this->assertInstanceOf(RequestBodyClientAuthenticationMethod::class, $endPoints->authenticationMethod('token', RequestBodyClientAuthenticationMethod::NAME));
    }

    public function test_authenticationMethod_with_supported_method_metadata_should_take_the_first()
    {
        $endPoints = $this->provider([
            'token_endpoint_auth_methods_supported' => [JwtBearerClientAuthenticationMethod::NAME, BasicClientAuthenticationMethod::NAME, RequestBodyClientAuthenticationMethod::NAME],
        ])->client((new ClientConfig('test')))->endPoints();

        $this->assertInstanceOf(JwtBearerClientAuthenticationMethod::class, $endPoints->authenticationMethod('token'));
    }

    public function test_authenticationMethod_with_supported_method_and_preferred_metadata_should_take_the_preferred_one_if_exists()
    {
        $endPoints = $this->provider([
            'token_endpoint_auth_methods_supported' => [JwtBearerClientAuthenticationMethod::NAME, BasicClientAuthenticationMethod::NAME, RequestBodyClientAuthenticationMethod::NAME],
        ])->client((new ClientConfig('test')))->endPoints();

        $this->assertInstanceOf(BasicClientAuthenticationMethod::class, $endPoints->authenticationMethod('token', BasicClientAuthenticationMethod::NAME));
    }

    public function test_authenticationMethod_with_supported_method_and_preferred_metadata_should_take_the_first_supported_if_preferred_one_do_not_exists()
    {
        $endPoints = $this->provider([
            'token_endpoint_auth_methods_supported' => [JwtBearerClientAuthenticationMethod::NAME, RequestBodyClientAuthenticationMethod::NAME],
        ])->client((new ClientConfig('test')))->endPoints();

        $this->assertInstanceOf(JwtBearerClientAuthenticationMethod::class, $endPoints->authenticationMethod('token', BasicClientAuthenticationMethod::NAME));
    }

    public function test_authenticationMethod_with_supported_but_first_not_implemented_should_take_basic()
    {
        $provider = $this->provider([
            'token_endpoint_auth_methods_supported' => ['not_implemented', RequestBodyClientAuthenticationMethod::NAME, BasicClientAuthenticationMethod::NAME],
        ]);
        $endPoints = $provider->client((new ClientConfig('test')))->endPoints();

        $this->assertInstanceOf(BasicClientAuthenticationMethod::class, $endPoints->authenticationMethod('token'));

        $selectedMethod = null;
        foreach ($provider->availableAuthenticationMethods() as $method) {
            if ($method instanceof BasicClientAuthenticationMethod) {
                $selectedMethod = $method;
                break;
            }
        }

        $this->assertSame($selectedMethod, $endPoints->authenticationMethod('token'));
    }

    public function test_authenticationMethod_with_supported_but_none_implemented_should_take_basic()
    {
        $endPoints = $this->provider([
            'token_endpoint_auth_methods_supported' => ['not_implemented'],
        ])->client((new ClientConfig('test')))->endPoints();

        $this->assertInstanceOf(BasicClientAuthenticationMethod::class, $endPoints->authenticationMethod('token'));
    }

    public function test_authenticationMethod_with_signing_alg()
    {
        $provider = $this->provider([
            'token_endpoint_auth_methods_supported' => [BasicClientAuthenticationMethod::NAME, JwtBearerClientAuthenticationMethod::NAME, RequestBodyClientAuthenticationMethod::NAME],
            'token_endpoint_auth_signing_alg_values_supported' => ['HS512'],
        ]);
        $endPoints = $provider->client((new ClientConfig('test')))->endPoints();

        $this->assertInstanceOf(JwtBearerClientAuthenticationMethod::class, $endPoints->authenticationMethod('token', JwtBearerClientAuthenticationMethod::NAME));

        $selectedMethod = null;
        foreach ($provider->availableAuthenticationMethods() as $method) {
            if ($method instanceof JwtBearerClientAuthenticationMethod) {
                $selectedMethod = $method;
                break;
            }
        }

        $this->assertEquals($selectedMethod->withSigningAlgorithms(['HS512']), $endPoints->authenticationMethod('token', JwtBearerClientAuthenticationMethod::NAME));
    }
}
