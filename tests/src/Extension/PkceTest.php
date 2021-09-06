<?php

namespace Parroauth2\Client\Extension;

use Nyholm\Psr7\Response;
use Parroauth2\Client\Client;
use Parroauth2\Client\ClientConfig;
use Parroauth2\Client\Tests\UnitTestCase;

/**
 * Class PkceTest
 */
class PkceTest extends UnitTestCase
{
    /**
     * @var Client
     */
    private $client;

    protected function setUp(): void
    {
        parent::setUp();

        $this->client = $this->provider()->client((new ClientConfig('test')));
        $this->client->register(new Pkce());
    }

    /**
     * 
     */
    public function test_configure_twice_should_not_modify_extension()
    {
        $pkce = new Pkce();

        $pkce->configure($this->client);
        $cloned = clone $pkce;

        $otherClient = $this->provider()->client((new ClientConfig('other')));
        $pkce->configure($otherClient);

        $this->assertEquals($cloned, $pkce);
    }

    /**
     *
     */
    public function test_authorization()
    {
        $authorization = $this->client->endPoints()->authorization();

        $this->assertTrue($this->session->has('code_verifier'));
        $this->assertEquals(128, strlen($this->session->retrieve('code_verifier')));
        $this->assertNotEmpty($authorization->get('code_challenge'));
        $this->assertEquals('S256', $authorization->get('code_challenge_method'));
    }

    /**
     *
     */
    public function test_authorization_force_plain()
    {
        $this->client->clientConfig()->setOption('code_challenge_method', 'plain');
        $authorization = $this->client->endPoints()->authorization();

        $this->assertTrue($this->session->has('code_verifier'));
        $this->assertEquals($this->session->retrieve('code_verifier'), $authorization->get('code_challenge'));
        $this->assertEquals('plain', $authorization->get('code_challenge_method'));
    }

    /**
     *
     */
    public function test_authorization_invalid_method()
    {
        $this->expectException(\LogicException::class);

        $this->client->clientConfig()->setOption('code_challenge_method', 'invalid');
        $this->client->endPoints()->authorization();
    }

    /**
     *
     */
    public function test_authorization_S256_not_supported_by_provider()
    {
        $this->client = $this->provider(['code_challenge_methods_supported' => ['plain']])->client(new ClientConfig('test'));
        $this->client->register(new Pkce($this->client));

        $authorization = $this->client->endPoints()->authorization();

        $this->assertTrue($this->session->has('code_verifier'));
        $this->assertEquals($this->session->retrieve('code_verifier'), $authorization->get('code_challenge'));
        $this->assertEquals('plain', $authorization->get('code_challenge_method'));
    }

    /**
     *
     */
    public function test_token()
    {
        $this->client->endPoints()->authorization();
        $codeVerifier = $this->session->retrieve('code_verifier');

        $this->httpClient->addResponse(new Response(200, [], '{}'));

        $token = $this->client->endPoints()->token();
        $token->call();

        $request = $this->httpClient->getLastRequest();

        $this->assertEquals('code_verifier='.$codeVerifier, (string) $request->getBody());
    }
}
