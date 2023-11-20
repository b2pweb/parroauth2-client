# Changelog

## v1.4.0

- Handle extra parameters on authorization endpoint (SSO-70)
  - Add $parameters argument on `Parroauth2\Client\EndPoint\Authorization\AuthorizationEndPoint::uri()`
  - Add $parameters argument on `Parroauth2\Client\Flow\AuthorizationFlowInterface::authorizationUri()`
- Use `b2pweb/jwt` library for JWT management (SSO-67)

## v1.3.0

- Add support of the end point client credentials.

## v1.2.0

- Compatibility with PHP 8.2, web-token v3.0 and psr/simple-cache v3.0
- Send `Content-Type: application/x-www-form-urlencoded` header by default on POST requests

## v1.1.0

- Add default config for all providers using `$default` constructor parameter of `ProviderConfigPool`
- Use configuration `default_headers` as associative array for declare defaults request headers on a provider, with key as header name and value as header value
