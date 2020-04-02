<?php

use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use OAuth2\GrantType\RefreshToken;
use OAuth2\GrantType\UserCredentials;
use OAuth2\OpenID\GrantType\AuthorizationCode;
use OAuth2\Request;
use OAuth2\Response;
use OAuth2\Server;
use OAuth2\Storage\Memory;
use Parroauth2\Client\Tests\TestingDataSet;

require_once __DIR__.'/../vendor/autoload.php';

const BASE_URL = 'http://localhost:5000';

$dataSet = new TestingDataSet();
$dataSet->declare();

$parameters = $dataSet->getConfig();

$storage = new \OAuth2\Storage\Pdo('sqlite:'.TestingDataSet::DB_FILE);
$server = new Server(
    $storage,
    [
        'enforce_state' => true,
        'allow_implicit' => false,
        'use_openid_connect' => true,
        'issuer' => BASE_URL,
    ] + $parameters,
    [
        'authorization_code' => new AuthorizationCode($storage),
        'user_credentials'   => new UserCredentials($storage),
        'refresh_token'      => new RefreshToken($storage, ['always_issue_new_refresh_token' => true]),
    ]
);
$server->addStorage(
    new Memory([
        'keys' => [
            'public_key'  => file_get_contents(__DIR__.'/keys/oauth-public.key'),
            'private_key' => file_get_contents(__DIR__.'/keys/oauth-private.key'),
        ]
    ]),
    'public_key'
);

$request = Request::createFromGlobals();

switch (trim($_SERVER['SCRIPT_NAME'] ?? '', '/')) {
    case 'authorize':
        $server->handleAuthorizeRequest($request, new Response(), true, $parameters['connected_user'] ?? null)->send();
        break;

    case 'token':
        $server->handleTokenRequest($request)->send();
        break;

    case 'revoke':
        $server->handleRevokeRequest($request)->send();
        break;

    case 'introspection':
        $token = $storage->getAccessToken($request->request('token'));

        if (!$token) {
            (new Response(['active' => false]))->send();
        } else {
            (new Response(['active' => true] + $token))->send();
        }
        break;

    case 'userinfo':
        $server->handleUserInfoRequest($request)->send();
        break;

    case '.well-known/openid-configuration':
        $response = new Response([
            'issuer'                 => BASE_URL,
            'authorization_endpoint' => BASE_URL.'/authorize',
            'token_endpoint'         => BASE_URL.'/token',
            'revocation_endpoint'    => BASE_URL.'/revoke',
            'userinfo_endpoint'    => BASE_URL.'/userinfo',
            'jwks_uri'               => BASE_URL.'/.well-known/jwks.json',
            'introspection_endpoint' => BASE_URL.'/introspection', // Added for allow local introspection
            'end_session_endpoint' => BASE_URL.'/logout',
        ]);
        $response->send();
        break;

    case '.well-known/jwks.json':
        $jwks = new JWKSet([
            JWKFactory::createFromKeyFile(__DIR__.'/keys/oauth-public.key', null, [
                'use' => 'sig',
                'alg' => 'RS256',
            ]),
        ]);
        $response = new Response($jwks->jsonSerialize());
        $response->send();
        break;

    default:
        http_response_code(404);
        echo 'not found';
}
