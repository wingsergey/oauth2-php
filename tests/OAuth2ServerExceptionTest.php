<?php

use OAuth2\OAuth2;
use OAuth2\OAuth2AuthenticateException;
use OAuth2\OAuth2RedirectException;
use OAuth2\OAuth2ServerException;
use Symfony\Component\HttpFoundation\Response;

/**
 * Covers how OAuth2 errors turn into HTTP responses.
 *
 * getHttpResponse() is what integrations actually call to answer a failed request
 * (the bundle uses it in its token and authorize controllers, and in its security
 * entry point), so the status code, headers and JSON body all matter.
 */
class OAuth2ServerExceptionTest extends \PHPUnit\Framework\TestCase
{
// OAuth2ServerException

    public function testExposesCodeErrorAndDescription()
    {
        $e = new OAuth2ServerException(Response::HTTP_BAD_REQUEST, OAuth2::ERROR_INVALID_REQUEST, 'Missing parameter');

        $this->assertSame(Response::HTTP_BAD_REQUEST, $e->getHttpCode());
        $this->assertSame(OAuth2::ERROR_INVALID_REQUEST, $e->getMessage());
        $this->assertSame('Missing parameter', $e->getDescription());
    }

    public function testDescriptionIsOptional()
    {
        $e = new OAuth2ServerException(Response::HTTP_BAD_REQUEST, OAuth2::ERROR_INVALID_REQUEST);

        $this->assertNull($e->getDescription());
        $this->assertSame(
            array('error' => OAuth2::ERROR_INVALID_REQUEST, 'error_description' => null),
            json_decode($e->getResponseBody(), true)
        );
    }

    public function testResponseBodyIsTheJsonErrorPayload()
    {
        $e = new OAuth2ServerException(Response::HTTP_BAD_REQUEST, OAuth2::ERROR_INVALID_GRANT, 'Invalid refresh token');

        $this->assertSame(
            array('error' => OAuth2::ERROR_INVALID_GRANT, 'error_description' => 'Invalid refresh token'),
            json_decode($e->getResponseBody(), true)
        );
    }

    public function testResponseHeadersForbidCaching()
    {
        $headers = (new OAuth2ServerException(Response::HTTP_BAD_REQUEST, OAuth2::ERROR_INVALID_REQUEST))->getResponseHeaders();

        $this->assertSame('application/json', $headers['Content-Type']);
        $this->assertSame('no-store', $headers['Cache-Control']);
        $this->assertSame('no-cache', $headers['Pragma']);
    }

    public function testGetHttpResponseCarriesStatusBodyAndHeaders()
    {
        $e = new OAuth2ServerException(Response::HTTP_BAD_REQUEST, OAuth2::ERROR_INVALID_REQUEST, 'Missing parameter');

        $response = $e->getHttpResponse();

        $this->assertInstanceOf(Response::class, $response);
        $this->assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        $this->assertSame('application/json', $response->headers->get('Content-Type'));
        // Symfony appends "private" to the directive it was given
        $this->assertStringContainsString('no-store', $response->headers->get('Cache-Control'));
        $this->assertSame(
            array('error' => OAuth2::ERROR_INVALID_REQUEST, 'error_description' => 'Missing parameter'),
            json_decode($response->getContent(), true)
        );
    }

    public function testToStringIsTheResponseBody()
    {
        $e = new OAuth2ServerException(Response::HTTP_BAD_REQUEST, OAuth2::ERROR_INVALID_REQUEST, 'Missing parameter');

        $this->assertSame($e->getResponseBody(), (string) $e);
        $this->assertJson((string) $e);
    }

// OAuth2AuthenticateException

    public function testAuthenticateExceptionAddsAWwwAuthenticateHeader()
    {
        $e = new OAuth2AuthenticateException(
            Response::HTTP_UNAUTHORIZED, OAuth2::TOKEN_TYPE_BEARER, 'my realm', OAuth2::ERROR_INVALID_GRANT, 'The access token provided has expired.'
        );

        $response = $e->getHttpResponse();
        $header = $response->headers->get('WWW-Authenticate');

        $this->assertStringStartsWith('Bearer realm="my realm"', $header);
        $this->assertStringContainsString('error="'.OAuth2::ERROR_INVALID_GRANT.'"', $header);
        $this->assertStringContainsString('error_description="The access token provided has expired."', $header);
        // the base headers must survive the override
        $this->assertSame('application/json', $response->headers->get('Content-Type'));
        $this->assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
    }

    public function testAuthenticateExceptionReportsTheRequiredScope()
    {
        $e = new OAuth2AuthenticateException(
            Response::HTTP_FORBIDDEN, OAuth2::TOKEN_TYPE_BEARER, 'realm', OAuth2::ERROR_INSUFFICIENT_SCOPE, 'Not enough', 'admin'
        );

        $this->assertStringContainsString('scope="admin"', $e->getResponseHeaders()['WWW-Authenticate']);
        $this->assertSame('admin', json_decode($e->getResponseBody(), true)['scope']);
    }

    public function testAuthenticateExceptionQuotesHostileRealmValues()
    {
        $e = new OAuth2AuthenticateException(
            Response::HTTP_UNAUTHORIZED, OAuth2::TOKEN_TYPE_BEARER, "re\"alm\r\nX-Injected: 1", OAuth2::ERROR_INVALID_GRANT
        );

        $header = $e->getResponseHeaders()['WWW-Authenticate'];

        // CRLF is stripped and the quote escaped, so the header cannot be broken out of
        $this->assertStringNotContainsString("\n", $header);
        $this->assertStringNotContainsString("\r", $header);
        // SP is legal inside a quoted-string, only the line break had to go
        $this->assertStringStartsWith('Bearer realm="re\\"almX-Injected: 1"', $header);
    }

// OAuth2RedirectException

    public function testRedirectExceptionRedirectsWithErrorInQuery()
    {
        $e = new OAuth2RedirectException('http://www.example.com/callback', OAuth2::ERROR_USER_DENIED, 'Denied', 'my-state');

        $response = $e->getHttpResponse();
        $location = $response->headers->get('Location');

        $this->assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        $this->assertStringStartsWith('http://www.example.com/callback?', $location);
        parse_str(parse_url($location, PHP_URL_QUERY), $params);
        $this->assertSame(OAuth2::ERROR_USER_DENIED, $params['error']);
        $this->assertSame('Denied', $params['error_description']);
        $this->assertSame('my-state', $params['state']);
    }

    public function testRedirectExceptionCanReportInTheFragment()
    {
        $e = new OAuth2RedirectException(
            'http://www.example.com/callback', OAuth2::ERROR_USER_DENIED, null, null, OAuth2::TRANSPORT_FRAGMENT
        );

        $location = $e->getResponseHeaders()['Location'];

        $this->assertStringContainsString('#error='.OAuth2::ERROR_USER_DENIED, $location);
    }

    public function testRedirectExceptionKeepsAnExistingQueryString()
    {
        $e = new OAuth2RedirectException('http://www.example.com/callback?foo=bar', OAuth2::ERROR_USER_DENIED);

        parse_str(parse_url($e->getResponseHeaders()['Location'], PHP_URL_QUERY), $params);

        $this->assertSame('bar', $params['foo']);
        $this->assertSame(OAuth2::ERROR_USER_DENIED, $params['error']);
    }
}
