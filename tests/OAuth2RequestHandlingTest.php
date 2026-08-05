<?php

use OAuth2\OAuth2;
use OAuth2\OAuth2ServerException;
use OAuth2\Model\OAuth2Client;
use OAuth2\Tests\Fixtures\OAuth2GrantUserStub;
use OAuth2\Tests\Fixtures\OAuth2StorageStub;
use Symfony\Component\HttpFoundation\Request;

/**
 * Covers how the endpoints read their input: POST bodies (what a real token endpoint
 * receives), the superglobals fallback when no Request is handed in, and bearer token
 * extraction from a form-encoded body.
 */
class OAuth2RequestHandlingTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @var array
     */
    private $globals = array();

    protected function setUp(): void
    {
        $this->globals = array('get' => $_GET, 'post' => $_POST, 'server' => $_SERVER);
    }

    protected function tearDown(): void
    {
        $_GET = $this->globals['get'];
        $_POST = $this->globals['post'];
        $_SERVER = $this->globals['server'];
    }

// POST bodies — how the token endpoint is really called

    public function testTokenEndpointReadsAPostBody()
    {
        $stub = $this->passwordStorage();

        $response = (new OAuth2($stub))->grantAccessToken(Request::create('/token', 'POST', array(
            'grant_type' => OAuth2::GRANT_TYPE_USER_CREDENTIALS,
            'client_id' => 'cid',
            'client_secret' => 'cpass',
            'username' => 'foo',
            'password' => 'bar',
        )));

        $this->assertSame(200, $response->getStatusCode());
        $this->assertNotEmpty(json_decode($response->getContent(), true)['access_token']);
    }

    public function testQueryParametersAreIgnoredOnAPostRequest()
    {
        $stub = $this->passwordStorage();

        // the grant_type only lives in the query string, so a POST must not find it
        $request = Request::create('/token?grant_type='.OAuth2::GRANT_TYPE_USER_CREDENTIALS, 'POST', array(
            'client_id' => 'cid', 'client_secret' => 'cpass', 'username' => 'foo', 'password' => 'bar',
        ));

        $this->expectException(OAuth2ServerException::class);
        $this->expectExceptionMessage(OAuth2::ERROR_INVALID_REQUEST);
        (new OAuth2($stub))->grantAccessToken($request);
    }

// Superglobals fallback

    public function testTokenEndpointFallsBackToTheSuperglobals()
    {
        $stub = $this->passwordStorage();

        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_POST = array(
            'grant_type' => OAuth2::GRANT_TYPE_USER_CREDENTIALS,
            'client_id' => 'cid',
            'client_secret' => 'cpass',
            'username' => 'foo',
            'password' => 'bar',
        );

        $response = (new OAuth2($stub))->grantAccessToken();

        $this->assertSame(200, $response->getStatusCode());
        $this->assertNotEmpty(json_decode($response->getContent(), true)['access_token']);
    }

    public function testAuthorizeEndpointFallsBackToTheSuperglobals()
    {
        $stub = new \OAuth2\Tests\Fixtures\OAuth2GrantCodeStub();
        $stub->addClient(new OAuth2Client('cid', 'cpass', array('http://www.example.com/')));

        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_GET = array(
            'client_id' => 'cid',
            'response_type' => OAuth2::RESPONSE_TYPE_AUTH_CODE,
            'redirect_uri' => 'http://www.example.com/',
            'state' => 'xyz',
        );

        $response = (new OAuth2($stub))->finishClientAuthorization(true);

        $this->assertStringStartsWith('http://www.example.com/?', $response->headers->get('Location'));
        $this->assertNotNull($stub->getLastAuthCode());
    }

    public function testGetBearerTokenFallsBackToTheSuperglobals()
    {
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_GET = array(OAuth2::TOKEN_PARAM_NAME => 'a_token_from_the_query');

        $oauth2 = new OAuth2(new OAuth2StorageStub());

        $this->assertSame('a_token_from_the_query', $oauth2->getBearerToken());
    }

// Bearer token in a form-encoded body

    public function testBearerTokenIsReadFromAFormEncodedBody()
    {
        $request = Request::create(
            '/resource', 'POST', array(), array(), array(), array('CONTENT_TYPE' => 'application/x-www-form-urlencoded'),
            OAuth2::TOKEN_PARAM_NAME.'=a_token_from_the_body'
        );

        $oauth2 = new OAuth2(new OAuth2StorageStub());

        $this->assertSame('a_token_from_the_body', $oauth2->getBearerToken($request));
    }

    public function testBearerTokenIsRemovedFromTheRequestWhenAsked()
    {
        $request = Request::create(
            '/resource', 'POST', array(OAuth2::TOKEN_PARAM_NAME => 'a_token_from_the_body'), array(), array(),
            array('CONTENT_TYPE' => 'application/x-www-form-urlencoded'),
            OAuth2::TOKEN_PARAM_NAME.'=a_token_from_the_body'
        );

        $oauth2 = new OAuth2(new OAuth2StorageStub());
        $token = $oauth2->getBearerToken($request, true);

        $this->assertSame('a_token_from_the_body', $token);
        $this->assertFalse($request->request->has(OAuth2::TOKEN_PARAM_NAME));
    }

    public function testFormEncodedBodyIsIgnoredOnAGetRequest()
    {
        // a GET carrying a form-encoded body is not a valid way to present a token
        $request = Request::create(
            '/resource', 'GET', array(), array(), array(), array('CONTENT_TYPE' => 'application/x-www-form-urlencoded'),
            OAuth2::TOKEN_PARAM_NAME.'=a_token_from_the_body'
        );

        $oauth2 = new OAuth2(new OAuth2StorageStub());

        $this->assertNull($oauth2->getBearerToken($request));
    }

    public function testBodyWithoutAFormContentTypeIsIgnored()
    {
        $request = Request::create(
            '/resource', 'POST', array(), array(), array(), array('CONTENT_TYPE' => 'application/json'),
            json_encode(array(OAuth2::TOKEN_PARAM_NAME => 'a_token_from_the_body'))
        );

        $oauth2 = new OAuth2(new OAuth2StorageStub());

        $this->assertNull($oauth2->getBearerToken($request));
    }

// Utility methods

    private function passwordStorage(): OAuth2GrantUserStub
    {
        $stub = new OAuth2GrantUserStub();
        $stub->addClient(new OAuth2Client('cid', 'cpass'));
        $stub->addUser('foo', 'bar');
        $stub->setAllowedGrantTypes(array(OAuth2::GRANT_TYPE_USER_CREDENTIALS));

        return $stub;
    }
}
