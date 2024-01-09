<?php

namespace Parroauth2\Client\Authentication;

use B2pweb\Jwt\JWT;
use B2pweb\Jwt\JwtEncoder;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Request;
use Parroauth2\Client\ClientConfig;
use Parroauth2\Client\Jwt\JwtDecoder;
use Parroauth2\Client\Tests\UnitTestCase;

class JwtBearerClientAuthenticationMethodTest extends UnitTestCase
{
    private $method;

    protected function setUp(): void
    {
        parent::setUp();

        $this->method = new JwtBearerClientAuthenticationMethod(new Psr17Factory(), new JwtEncoder());
    }

    public function test_without_secret()
    {
        $this->expectException(\InvalidArgumentException::class);
        $client = $this->provider()->client((new ClientConfig('my_client')));

        $this->method->apply($client, new Request('GET', 'http://foo.com'));
    }

    public function test_with_secret()
    {
        $client = $this->provider()->client((new ClientConfig('my_client'))->setSecret('my-secretmy-secretmy-secretmy-secretmy-secretmy-secretmy-secret'));

        $request = $this->method->apply($client, new Request('GET', 'http://foo.com?foo=bar&baz=qux'));

        $body = (string) $request->getBody();
        parse_str($body, $data);

        $this->assertEquals('client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion=' . $data['client_assertion'], $body);

        $jwt = JWT::fromJwtUnsafe($data['client_assertion']);
        $this->assertEquals(['alg' => 'HS256'], $jwt->headers());
        $this->assertEqualsWithDelta([
            'iss' => 'my_client',
            'sub' => 'my_client',
            'aud' => 'http://foo.com',
            'exp' => time() + 30,
            'iat' => time(),
            'nbf' => time(),
            'jti' => $jwt->payload()['jti'],
        ], $jwt->payload(), 2);

        $this->assertRegExp('/^[a-zA-Z0-9-_]{32}$/', $jwt->payload()['jti']);

        (new JwtDecoder())->decode($data['client_assertion'],
            new JWKSet([
                JWKFactory::createFromSecret($client->secret(), ['alg' => 'HS256'])
            ])
        );
    }

    public function test_with_body()
    {
        $client = $this->provider()->client((new ClientConfig('my_client'))->setSecret('my-secretmy-secretmy-secretmy-secretmy-secretmy-secretmy-secret'));

        $request = $this->method->apply($client, (new Request('GET', 'http://foo.com'))->withBody((new Psr17Factory())->createStream('foo=bar&baz=qux')));

        $body = (string) $request->getBody();
        parse_str($body, $data);

        $this->assertEquals('foo=bar&baz=qux&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion=' . $data['client_assertion'], $body);

        $jwt = JWT::fromJwtUnsafe($data['client_assertion']);
        $this->assertEquals(['alg' => 'HS256'], $jwt->headers());
        $this->assertEqualsWithDelta([
            'iss' => 'my_client',
            'sub' => 'my_client',
            'aud' => 'http://foo.com',
            'exp' => time() + 30,
            'iat' => time(),
            'nbf' => time(),
            'jti' => $jwt->payload()['jti'],
        ], $jwt->payload(), 2);

        $this->assertRegExp('/^[a-zA-Z0-9-_]{32}$/', $jwt->payload()['jti']);

        (new JwtDecoder())->decode($data['client_assertion'],
            new JWKSet([
                JWKFactory::createFromSecret($client->secret(), ['alg' => 'HS256'])
            ])
        );
    }

    public function test_withSigningAlgorithms()
    {
        $this->assertNotSame($this->method, $this->method->withSigningAlgorithms(['HS256']));

        $method = $this->method->withSigningAlgorithms(['HS384', 'HS512']);
        $client = $this->provider()->client((new ClientConfig('my_client'))->setSecret('my-secretmy-secretmy-secretmy-secretmy-secretmy-secretmy-secret'));
        $request = $method->apply($client, (new Request('GET', 'http://foo.com'))->withBody((new Psr17Factory())->createStream('foo=bar&baz=qux')));

        $body = (string) $request->getBody();
        parse_str($body, $data);

        $jwt = JWT::fromJwtUnsafe($data['client_assertion']);
        $this->assertEquals(['alg' => 'HS384'], $jwt->headers());
        $this->assertEqualsWithDelta([
            'iss' => 'my_client',
            'sub' => 'my_client',
            'aud' => 'http://foo.com',
            'exp' => time() + 30,
            'iat' => time(),
            'nbf' => time(),
            'jti' => $jwt->payload()['jti'],
        ], $jwt->payload(), 2);

        $this->assertRegExp('/^[a-zA-Z0-9-_]{32}$/', $jwt->payload()['jti']);

        (new JwtDecoder())->decode($data['client_assertion'],
            new JWKSet([
                JWKFactory::createFromSecret($client->secret(), ['alg' => 'HS384'])
            ])
        );
    }

    public function test_name()
    {
        $this->assertSame('client_secret_jwt', $this->method->name());
    }

    public function test_option_issuer()
    {
        $client = $this->provider()->client((new ClientConfig('my_client'))
            ->setSecret('my-secretmy-secretmy-secretmy-secretmy-secretmy-secretmy-secret')
            ->setOption(JwtBearerClientAuthenticationMethod::OPTION_ISSUER, 'my_issuer')
        );

        $request = $this->method->apply($client, new Request('GET', 'http://foo.com?foo=bar&baz=qux'));

        $body = (string) $request->getBody();
        parse_str($body, $data);

        $this->assertEquals('client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion=' . $data['client_assertion'], $body);

        $jwt = JWT::fromJwtUnsafe($data['client_assertion']);
        $this->assertEquals(['alg' => 'HS256'], $jwt->headers());
        $this->assertEqualsWithDelta([
            'iss' => 'my_issuer',
            'sub' => 'my_client',
            'aud' => 'http://foo.com',
            'exp' => time() + 30,
            'iat' => time(),
            'nbf' => time(),
            'jti' => $jwt->payload()['jti'],
        ], $jwt->payload(), 2);

        $this->assertRegExp('/^[a-zA-Z0-9-_]{32}$/', $jwt->payload()['jti']);

        (new JwtDecoder())->decode($data['client_assertion'],
            new JWKSet([
                JWKFactory::createFromSecret($client->secret(), ['alg' => 'HS256'])
            ])
        );
    }

    public function test_option_audience()
    {
        $client = $this->provider()->client((new ClientConfig('my_client'))
            ->setSecret('my-secretmy-secretmy-secretmy-secretmy-secretmy-secretmy-secret')
            ->setOption(JwtBearerClientAuthenticationMethod::OPTION_AUDIENCE, 'my_audience')
        );

        $request = $this->method->apply($client, new Request('GET', 'http://foo.com?foo=bar&baz=qux'));

        $body = (string) $request->getBody();
        parse_str($body, $data);

        $this->assertEquals('client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion=' . $data['client_assertion'], $body);

        $jwt = JWT::fromJwtUnsafe($data['client_assertion']);
        $this->assertEquals(['alg' => 'HS256'], $jwt->headers());
        $this->assertEqualsWithDelta([
            'iss' => 'my_client',
            'sub' => 'my_client',
            'aud' => 'my_audience',
            'exp' => time() + 30,
            'iat' => time(),
            'nbf' => time(),
            'jti' => $jwt->payload()['jti'],
        ], $jwt->payload(), 2);

        $this->assertRegExp('/^[a-zA-Z0-9-_]{32}$/', $jwt->payload()['jti']);

        (new JwtDecoder())->decode($data['client_assertion'],
            new JWKSet([
                JWKFactory::createFromSecret($client->secret(), ['alg' => 'HS256'])
            ])
        );
    }

    public function test_option_expiration()
    {
        $client = $this->provider()->client((new ClientConfig('my_client'))
            ->setSecret('my-secretmy-secretmy-secretmy-secretmy-secretmy-secretmy-secret')
            ->setOption(JwtBearerClientAuthenticationMethod::OPTION_EXPIRATION, 720)
        );

        $request = $this->method->apply($client, new Request('GET', 'http://foo.com?foo=bar&baz=qux'));

        $body = (string) $request->getBody();
        parse_str($body, $data);

        $this->assertEquals('client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion=' . $data['client_assertion'], $body);

        $jwt = JWT::fromJwtUnsafe($data['client_assertion']);
        $this->assertEquals(['alg' => 'HS256'], $jwt->headers());
        $this->assertEqualsWithDelta([
            'iss' => 'my_client',
            'sub' => 'my_client',
            'aud' => 'http://foo.com',
            'exp' => time() + 720,
            'iat' => time(),
            'nbf' => time(),
            'jti' => $jwt->payload()['jti'],
        ], $jwt->payload(), 2);

        $this->assertRegExp('/^[a-zA-Z0-9-_]{32}$/', $jwt->payload()['jti']);

        (new JwtDecoder())->decode($data['client_assertion'],
            new JWKSet([
                JWKFactory::createFromSecret($client->secret(), ['alg' => 'HS256'])
            ])
        );
    }

    public function test_option_algorithm()
    {
        $client = $this->provider()->client((new ClientConfig('my_client'))
            ->setSecret('my-secretmy-secretmy-secretmy-secretmy-secretmy-secretmy-secreta')
            ->setOption(JwtBearerClientAuthenticationMethod::OPTION_ALGORITHM, 'HS512')
        );

        $request = $this->method->apply($client, new Request('GET', 'http://foo.com?foo=bar&baz=qux'));

        $body = (string) $request->getBody();
        parse_str($body, $data);

        $this->assertEquals('client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion=' . $data['client_assertion'], $body);

        $jwt = JWT::fromJwtUnsafe($data['client_assertion']);
        $this->assertEquals(['alg' => 'HS512'], $jwt->headers());
        $this->assertEqualsWithDelta([
            'iss' => 'my_client',
            'sub' => 'my_client',
            'aud' => 'http://foo.com',
            'exp' => time() + 30,
            'iat' => time(),
            'nbf' => time(),
            'jti' => $jwt->payload()['jti'],
        ], $jwt->payload(), 2);

        $this->assertRegExp('/^[a-zA-Z0-9-_]{32}$/', $jwt->payload()['jti']);

        (new JwtDecoder())->decode($data['client_assertion'],
            new JWKSet([
                JWKFactory::createFromSecret($client->secret(), ['alg' => 'HS512'])
            ])
        );
    }
}
