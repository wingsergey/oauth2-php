OAuth2 Server Implementation
============================

[![Tests](https://github.com/klapaudius/oauth2-php/actions/workflows/coverage.yml/badge.svg?branch=master)](https://github.com/klapaudius/oauth2-php/actions/workflows/coverage.yml)
[![codecov](https://codecov.io/gh/klapaudius/oauth2-php/graph/badge.svg?token=QJ6HNBJO31)](https://codecov.io/gh/klapaudius/oauth2-php)
![Packagist Downloads](https://img.shields.io/packagist/dt/klapaudius/oauth2-php)

An OAuth 2.0 **authorization server** for PHP, implementing draft 20 of the specification,
with the OpenID Connect hooks needed to issue `id_token` claims.

The library is framework-agnostic: it only depends on
[HttpFoundation](https://github.com/symfony/http-foundation) for request/response handling and
on [PSR-14](https://www.php-fig.org/psr/psr-14/) for its event hook. You provide the storage.

Requirements
------------

PHP 8.2 or later.

Installation
------------

```bash
composer require klapaudius/oauth2-php
```

Using Symfony? [klapaudius/oauth-server-bundle](https://github.com/klapaudius/FOSOAuthServerBundle)
wires this library into a Symfony application, with Doctrine ORM/ODM storage, controllers and a
security authenticator already provided.

Usage
-----

Implement the storage interface(s) matching the grant types you want to support, then let
`OAuth2` handle the endpoints:

```php
use OAuth2\OAuth2;

$oauth = new OAuth2($myStorage);

// Token endpoint — returns a HttpFoundation Response, either the token or the OAuth2 error
try {
    $response = $oauth->grantAccessToken($request);
} catch (\OAuth2\OAuth2ServerException $e) {
    $response = $e->getHttpResponse();
}

// Authorize endpoint, once the end-user has approved (or denied) the request
$response = $oauth->finishClientAuthorization($isApproved, $user, $request);

// Resource endpoint
$token = $oauth->verifyAccessToken($oauth->getBearerToken($request), 'my_scope');
```

Every failure is an `OAuth2ServerException` (or one of its subclasses,
`OAuth2AuthenticateException` and `OAuth2RedirectException`), and `getHttpResponse()` turns any
of them into the response the specification prescribes — right status code, JSON error body, or
redirect back to the client.

### Storage interfaces

`IOAuth2Storage` is mandatory; each grant type adds one interface to implement:

| Interface               | Enables                                        |
|-------------------------|------------------------------------------------|
| `IOAuth2Storage`        | client lookup and access tokens (required)     |
| `IOAuth2GrantCode`      | `authorization_code`                           |
| `IOAuth2GrantUser`      | `password`                                     |
| `IOAuth2GrantClient`    | `client_credentials`                           |
| `IOAuth2GrantImplicit`  | implicit flow (`response_type=token`)          |
| `IOAuth2RefreshTokens`  | `refresh_token`, including token rotation      |
| `IOAuth2GrantExtension` | extension grants (`urn:` or absolute URI)      |

You only implement what you actually serve: the token endpoint rejects a grant whose interface is
missing with `unsupported_grant_type`, and the authorize endpoint answers
`unsupported_response_type`.

OpenID Connect
--------------

The library issues OAuth2 tokens; it does not build `id_token` JWTs for you. Instead it publishes
an event on every successful grant, carrying everything an OIDC layer needs — including the
`nonce` and the authentication time bound to the authorization code:

```php
use OAuth2\OAuth2;
use OAuth2\OAuthTokenGrantedEvent;

$oauth = new OAuth2($myStorage, [], $eventDispatcher);
```

```php
public function onTokenGranted(OAuthTokenGrantedEvent $event): void
{
    $token = $event->getToken();
    $token['id_token'] = $this->buildIdToken(
        $event->getUser(),
        $event->getClient(),
        $event->getNonce(),      // the "nonce" sent to the authorize endpoint, replayed here
        $event->getAuthTime()    // when the end-user actually authenticated
    );
    $event->setToken($token);
}
```

Whatever you set with `setToken()` is what the client receives. Subscribe on
`OAuthTokenGrantedEvent::NAME`.

Two notes on these two values:

* `nonce` is read from the authorization request, stored on the authorization code by your
  storage, and handed back on the token request. It is `null` for grant types that involve no
  authorization code.
* `auth_time` is **never** read from the request — only your application knows when its user
  authenticated. Stamp it on the authorization code when you create it; left unset, it arrives
  as `null` and you simply omit the claim.

Upgrading
---------

Version 3.0 removes the legacy client-side implementation and detaches clients from the Symfony
security layer. See [CHANGELOG.txt](CHANGELOG.txt) for the BC breaks.

Contributing
------------

```bash
composer install
vendor/bin/phpunit          # test suite
vendor/bin/phpstan analyse  # static analysis, level 8
```

Both run in CI on PHP 8.2 through 8.5. Patches are expected to keep PHPStan clean at level 8 and
to come with tests.

History
-------

This library is a fork of https://github.com/quizlet/oauth2-php, itself a fork of
http://code.google.com/p/oauth2-php/ (the original, long abandoned). Compared to the quizlet
version it is namespaced, PSR-4 autoloaded, free of `require(_once)`, built on HttpFoundation,
and considerably better covered by tests.
