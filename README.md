# Parroauth2 Client
[![build](https://github.com/b2pweb/parroauth2-client/actions/workflows/php.yml/badge.svg)](https://github.com/b2pweb/parroauth2-client/actions/workflows/php.yml)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/b2pweb/parroauth2-client/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/b2pweb/parroauth2-client/?branch=master)
[![Code Coverage](https://scrutinizer-ci.com/g/b2pweb/parroauth2-client/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/b2pweb/parroauth2-client/?branch=master)
[![Packagist Version](https://img.shields.io/packagist/v/b2pweb/parroauth2-client.svg)](https://packagist.org/packages/b2pweb/parroauth2-client)
[![Total Downloads](https://img.shields.io/packagist/dt/b2pweb/parroauth2-client.svg)](https://packagist.org/packages/b2pweb/parroauth2-client)
[![Type Coverage](https://shepherd.dev/github/b2pweb/parroauth2-client/coverage.svg)](https://shepherd.dev/github/b2pweb/parroauth2-client)

OAuth 2.0 and OpenID Connect client library for PHP. 

## Installation

Install with composer :

```bash
composer require b2pweb/parroauth2-client
```

## Simple usage

For a simple usage, using **Authorization Server Metadata** [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414)
or [OpenID Connection discovery](https://openid.net/specs/openid-connect-discovery-1_0.html), you can see [example](./example) directory.

### [Password authentication](./example/password.php)

Authenticate to a provider using **password** grant type (cf: [RFC 6749#4.3](https://datatracker.ietf.org/doc/html/rfc6749#section-4.3)).

This example simply configure the OAuth 2.0 client, and call the token endpoint of the provider with owner's credentials (i.e. username and password).

### [Standard authentication flow](./example/standard.php)

Implements the client-side authentication using **authorization_code** grant type (cf: [RFC 6749#4.1](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1))
which is the recommended authorization flow.

- First the session storage is configured
- Then the provider and the client are loaded
- Register extensions
  - `JwtAccessToken` to enable local introspection of the access token
  - `Pkce` to enable PKCE [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) to mitigate authorization code interception attack
  - `IdTokenValidator` (only for OpenID) to enable verification of the ID Token
  - `TokenStorage` store the access token into session, and provide it into oauth endpoints
- Perform the authentication process if the token is not present or expired, by using `AuthorizationCodeFlow`
- Once authenticated, perform userinfo and introspection
- Also implements the **logout** action, using revocation endpoint and redirect to the OP for stop the session

### [Access token check on server side](./example/server_resource.php)

Check the access token passed as **Authorization: Bearer** header using local introspection.

## Advanced usage

### Configure provider manually

If the authentication provider do not implement the auto-discovery, or you want to configure manually,
you can use the `ProviderBuilder` :

```php
$loader = new \Parroauth2\Client\Provider\ProviderLoader();

// Configure and create the provider
$provider = $loader->builder('http://my-op.example.com')
    ->openid() // Enable openid connection on the endpoint

    // Configure endpoints
    ->tokenEndPoint('/token')
    ->authorizationEndPoint('/auth')
    ->introspectionEndPoint('/introspect')
    
    // Configure public key for local introspection
    ->addKeyFile('./keys/provider.pub')
    
    ->create()
;

// Create the client
$client = $provider->client((new \Parroauth2\Client\ClientConfig('client_id'))->setSecret('secret'));
```

### Lazy provider

In some case, you should delay the loading of the provider, and only load it when it's necessary.
This is necessary when use a dependency injection container which inject the client or the provider
into a service.

In this context you can use `ProviderLoader::lazy()`, which allows loading provider
only when calling OP endpoints.

### Design consideration

#### EndPoints

End points are immutable, any call to setters will return a new instance of the endpoint.

So the following code is invalid :

```php
/** @var $client \Parroauth2\Client\ClientInterface */
$token = $client->endPoints()->token();
$token->refresh('MyRefreshToken'); // This instruction has no effect : the return value is ignored

$token->call(); // This call will fail : no token has been provided
```

To save a state, like provide a token, you should use Extensions with an `EndPointTransformerInterface`,
or inject parameters manually at each endpoint calls.

#### Extensions

Extension consist of a class with single method `configure()` which takes the client as parameter.
They permit modifying or configuring any mutable elements of client like :
- Change client configuration
- Register or replace an end point
- Register an `EndPointTransformerInterface`

To simply apply an endpoint transformer, you can inherit `AbstractEndPointTransformerExtension`,
implement the desired endpoint transformation method, and use `CallableEndPointInterface::onResponse()`
to intercept responses.

> Note: because endpoints are immutable, the endpoint transformer must return the configured instance
> of the endpoint
