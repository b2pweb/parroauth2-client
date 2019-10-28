<?php
/**
 * Client example for implements the standard "code" grant type flow
 */

use Parroauth2\Client\ClientConfig;
use Parroauth2\Client\Extension\JwtAccessToken\JwtAccessToken;
use Parroauth2\Client\Extension\Pkce;
use Parroauth2\Client\Extension\TokenStorage;
use Parroauth2\Client\Factory\BaseClientFactory;
use Parroauth2\Client\Flow\AuthorizationCodeFlow;
use Parroauth2\Client\OpenID\Extension\IdTokenValidator;
use Parroauth2\Client\Provider\ProviderLoader;
use Parroauth2\Client\Storage\ArrayStorage;

require_once __DIR__.'/../vendor/autoload.php';

// Start the session system and storage
session_start();
$session = new ArrayStorage($_SESSION['oauth'] ?? []);
register_shutdown_function(function () use($session) { $_SESSION['oauth'] = $session->all(); });

// Load the provider
$loader = new ProviderLoader(new BaseClientFactory($session));
$provider = $loader->discover('http://192.168.0.139/~vquatrevieux/sso/s2pweb/oidc');

// Create the client
$client = $provider->client(
    (new ClientConfig('test_parroauth'))
        ->setSecret('tyiY2kmxhRC4T5TSEidXH9-a6K-8q3dQdn3OPAhtPNY')
);

// Register extensions
$client->register(new JwtAccessToken()); // Enable local introspection using JWT access token
$client->register(new Pkce()); // Enable PKCE check (only if supported by the server)
$client->register(new IdTokenValidator()); // Validate the ID Token (only for openid)
$client->register($storage = new TokenStorage()); // Automatically store and provide the access token

// Check if the token is valid
if ($storage->expired()) {
    // Start the "code" authentication flow
    $flow = new AuthorizationCodeFlow($client);

    // Handle the response of the authorization endpoint (/connect is registered as redirect_uri)
    if ($_SERVER['PATH_INFO'] ?? '/' === '/connect') {
        $flow->handleAuthorizationResponse($_GET);

        // User successfully authenticated : Redirect to home page
        header('Location: http://192.168.0.139/~vquatrevieux/test_parroauth/standard.php');
        return;
    }

    // Generate the authorization endpoint URL for start the authentication
    echo '<a href="'.$flow->authorizationUri('http://192.168.0.139/~vquatrevieux/test_parroauth/standard.php/connect').'">Me connecter</a>';
    return;
}

// logout : remove the session and revoke the token
if ($_SERVER['PATH_INFO'] ?? '/' === '/logout') {
    session_destroy();
    $client->endPoints()->revocation()->call(); // Note: the token is provided by the TokenStorage extension

    header('Location: http://192.168.0.139/~vquatrevieux/test_parroauth/standard.php');
    return;
}

echo 'Hello World !';
echo '<a href="http://192.168.0.139/~vquatrevieux/test_parroauth/standard.php/logout">Déconnexion</a><pre>';
// Perform operations on the token (which is provided by the TokenStorage extension)
var_dump($storage->token());
var_dump($client->endPoints()->userinfo()->call());
var_dump($client->endPoints()->introspection()->call());
echo '</pre>';
