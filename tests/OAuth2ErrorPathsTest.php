<?php

use OAuth2\OAuth2;
use OAuth2\OAuth2RedirectException;
use OAuth2\OAuth2ServerException;
use OAuth2\Model\OAuth2AuthCode;
use OAuth2\Model\OAuth2Client;
use OAuth2\Tests\Fixtures\OAuth2GrantCodeStub;
use OAuth2\Tests\Fixtures\OAuth2GrantUserStub;
use OAuth2\Tests\Fixtures\OAuth2StorageStub;
use Symfony\Component\HttpFoundation\Request;

/**
 * Covers the rejection paths of the token and authorize endpoints: what the server
 * answers when a client sends something wrong, or when the storage does not support
 * the grant that was asked for.
 */
class OAuth2ErrorPathsTest extends \PHPUnit\Framework\TestCase
{
// Client authentication, before any grant runs

    public function testUnknownClientIsRejected()
    {
        $stub = $this->storageWithClient();

        $this->assertServerException(
            OAuth2::ERROR_INVALID_CLIENT,
            'The client credentials are invalid',
            fn () => $this->token($stub, array('grant_type' => OAuth2::GRANT_TYPE_USER_CREDENTIALS, 'client_id' => 'ghost', 'client_secret' => 'cpass'))
        );
    }

    public function testMissingClientIdIsRejectedBeforeAnyStorageLookup()
    {
        $stub = $this->storageWithClient();

        $this->assertServerException(
            OAuth2::ERROR_INVALID_CLIENT,
            'Client id was not found in the headers or body',
            fn () => $this->token($stub, array('grant_type' => OAuth2::GRANT_TYPE_USER_CREDENTIALS))
        );
    }

    public function testWrongClientSecretIsRejected()
    {
        $stub = $this->storageWithClient();

        $this->assertServerException(
            OAuth2::ERROR_INVALID_CLIENT,
            'The client credentials are invalid',
            fn () => $this->token($stub, array('grant_type' => OAuth2::GRANT_TYPE_USER_CREDENTIALS, 'client_id' => 'cid', 'client_secret' => 'wrong'))
        );
    }

    public function testGrantTypeThatIsNeitherKnownNorAUriIsRejected()
    {
        $stub = $this->storageWithClient();
        $stub->setAllowedGrantTypes(array('not_a_grant'));

        $this->assertServerException(
            OAuth2::ERROR_INVALID_REQUEST,
            'Invalid grant_type parameter or parameter missing',
            fn () => $this->token($stub, array('grant_type' => 'not_a_grant', 'client_id' => 'cid', 'client_secret' => 'cpass'))
        );
    }

    public function testGrantTypeThatLooksValidButIsNotAGrantIsRejected()
    {
        // "token" passes GRANT_TYPE_REGEXP (it is a response_type) but no grant handles it,
        // and it is neither a urn: nor an absolute URI, so the extension path refuses it
        $stub = $this->storageWithClient();
        $stub->setAllowedGrantTypes(array('token'));

        $this->assertServerException(
            OAuth2::ERROR_INVALID_REQUEST,
            'Invalid grant_type parameter or parameter missing',
            fn () => $this->token($stub, array('grant_type' => 'token', 'client_id' => 'cid', 'client_secret' => 'cpass'))
        );
    }

    public function testUnauthorizedGrantTypeForTheClientIsRejected()
    {
        $stub = new OAuth2StorageStub();
        $stub->addClient(new OAuth2Client('cid', 'cpass'));
        $stub->setAllowedGrantTypes(array(OAuth2::GRANT_TYPE_AUTH_CODE));

        $this->assertServerException(
            OAuth2::ERROR_UNAUTHORIZED_CLIENT,
            'The grant type is unauthorized for this client_id',
            fn () => $this->token($stub, array(
                'grant_type' => OAuth2::GRANT_TYPE_CLIENT_CREDENTIALS, 'client_id' => 'cid', 'client_secret' => 'cpass',
            ))
        );
    }

// authorization_code grant

    public function testAuthCodeGrantIsUnsupportedWhenTheStorageCannotStoreCodes()
    {
        $storage = $this->bareStorage();

        $this->assertServerException(
            OAuth2::ERROR_UNSUPPORTED_GRANT_TYPE,
            null,
            fn () => $this->token($storage, array(
                'grant_type' => OAuth2::GRANT_TYPE_AUTH_CODE, 'client_id' => 'cid', 'client_secret' => 'cpass',
                'code' => 'foo', 'redirect_uri' => 'http://www.example.com/',
            ))
        );
    }

    public function testExpiredAuthCodeIsRejected()
    {
        $stub = new OAuth2GrantCodeStub();
        $stub->addClient(new OAuth2Client('cid', 'cpass', array('http://www.example.com/')));
        $stub->setAllowedGrantTypes(array(OAuth2::GRANT_TYPE_AUTH_CODE));
        $stub->createAuthCode('foo', $stub->getClient('cid'), null, 'http://www.example.com/', time() - 1);

        $this->assertServerException(
            OAuth2::ERROR_INVALID_GRANT,
            'The authorization code has expired',
            fn () => $this->token($stub, array(
                'grant_type' => OAuth2::GRANT_TYPE_AUTH_CODE, 'client_id' => 'cid', 'client_secret' => 'cpass',
                'code' => 'foo', 'redirect_uri' => 'http://www.example.com/',
            ))
        );
    }

    public function testRedirectUriIsRejectedWhenTheCodeWasIssuedWithoutOne()
    {
        // validateRedirectUri() treats a missing stored URI as invalid rather than as a wildcard
        $stub = new OAuth2GrantCodeStub();
        $stub->addClient(new OAuth2Client('cid', 'cpass', array('http://www.example.com/')));
        $stub->setAllowedGrantTypes(array(OAuth2::GRANT_TYPE_AUTH_CODE));
        $stub->createAuthCode('foo', $stub->getClient('cid'), null, null, time() + 60);

        $this->assertServerException(
            OAuth2::ERROR_REDIRECT_URI_MISMATCH,
            'The redirect URI is missing or do not match',
            fn () => $this->token($stub, array(
                'grant_type' => OAuth2::GRANT_TYPE_AUTH_CODE, 'client_id' => 'cid', 'client_secret' => 'cpass',
                'code' => 'foo', 'redirect_uri' => 'http://www.example.com/',
            ))
        );
    }

    public function testUnparsableRedirectUriIsRejected()
    {
        $stub = new OAuth2GrantCodeStub();
        $stub->addClient(new OAuth2Client('cid', 'cpass', array('http://www.example.com/')));
        $stub->setAllowedGrantTypes(array(OAuth2::GRANT_TYPE_AUTH_CODE));
        $stub->createAuthCode('foo', $stub->getClient('cid'), null, 'http://www.example.com/', time() + 60);

        $this->assertServerException(
            OAuth2::ERROR_REDIRECT_URI_MISMATCH,
            'The redirect URI is missing or do not match',
            fn () => $this->token($stub, array(
                'grant_type' => OAuth2::GRANT_TYPE_AUTH_CODE, 'client_id' => 'cid', 'client_secret' => 'cpass',
                'code' => 'foo', 'redirect_uri' => 'http://:80',
            ))
        );
    }

// password grant

    public function testUserCredentialsGrantIsUnsupportedWhenTheStorageCannotCheckThem()
    {
        $this->assertServerException(
            OAuth2::ERROR_UNSUPPORTED_GRANT_TYPE,
            null,
            fn () => $this->token($this->bareStorage(), array(
                'grant_type' => OAuth2::GRANT_TYPE_USER_CREDENTIALS, 'client_id' => 'cid', 'client_secret' => 'cpass',
                'username' => 'foo', 'password' => 'bar',
            ))
        );
    }

    public function testUserCredentialsGrantRequiresBothUsernameAndPassword()
    {
        $stub = new OAuth2GrantUserStub();
        $stub->addClient(new OAuth2Client('cid', 'cpass'));
        $stub->setAllowedGrantTypes(array(OAuth2::GRANT_TYPE_USER_CREDENTIALS));

        $this->assertServerException(
            OAuth2::ERROR_INVALID_REQUEST,
            'Missing parameters. "username" and "password" required',
            fn () => $this->token($stub, array(
                'grant_type' => OAuth2::GRANT_TYPE_USER_CREDENTIALS, 'client_id' => 'cid', 'client_secret' => 'cpass',
                'username' => 'foo',
            ))
        );
    }

    public function testUnknownUserCredentialsAreRejected()
    {
        $stub = new OAuth2GrantUserStub();
        $stub->addClient(new OAuth2Client('cid', 'cpass'));
        $stub->addUser('foo', 'bar');
        $stub->setAllowedGrantTypes(array(OAuth2::GRANT_TYPE_USER_CREDENTIALS));

        $this->assertServerException(
            OAuth2::ERROR_INVALID_GRANT,
            'Invalid username and password combination',
            fn () => $this->token($stub, array(
                'grant_type' => OAuth2::GRANT_TYPE_USER_CREDENTIALS, 'client_id' => 'cid', 'client_secret' => 'cpass',
                'username' => 'foo', 'password' => 'not_bar',
            ))
        );
    }

// client_credentials grant

    public function testClientCredentialsGrantIsUnsupportedWhenTheStorageDoesNotOfferIt()
    {
        $this->assertServerException(
            OAuth2::ERROR_UNSUPPORTED_GRANT_TYPE,
            null,
            fn () => $this->token($this->bareStorage(), array(
                'grant_type' => OAuth2::GRANT_TYPE_CLIENT_CREDENTIALS, 'client_id' => 'cid', 'client_secret' => 'cpass',
            ))
        );
    }

    public function testClientCredentialsGrantRequiresASecret()
    {
        // a public client (no secret) authenticates fine, but this grant still demands one
        $stub = new OAuth2StorageStub();
        $stub->addClient(new OAuth2Client('cid'));
        $stub->setAllowedGrantTypes(array(OAuth2::GRANT_TYPE_CLIENT_CREDENTIALS));

        $this->assertServerException(
            OAuth2::ERROR_INVALID_CLIENT,
            'The client_secret is mandatory for the "client_credentials" grant type',
            fn () => $this->token($stub, array('grant_type' => OAuth2::GRANT_TYPE_CLIENT_CREDENTIALS, 'client_id' => 'cid'))
        );
    }

    public function testClientCredentialsGrantRejectedByTheStorageIsAnInvalidGrant()
    {
        $storage = $this->createMock('OAuth2\IOAuth2GrantClient');
        $storage->expects($this->any())->method('getClient')->willReturn(new OAuth2Client('cid', 'cpass'));
        $storage->expects($this->any())->method('checkClientCredentials')->willReturn(true);
        $storage->expects($this->any())->method('checkRestrictedGrantType')->willReturn(true);
        $storage->expects($this->any())->method('checkClientCredentialsGrant')->willReturn(false);

        $this->assertServerException(
            OAuth2::ERROR_INVALID_GRANT,
            null,
            fn () => $this->token($storage, array(
                'grant_type' => OAuth2::GRANT_TYPE_CLIENT_CREDENTIALS, 'client_id' => 'cid', 'client_secret' => 'cpass',
            ))
        );
    }

// extension grants

    public function testExtensionGrantIsUnsupportedWhenTheStorageDoesNotOfferIt()
    {
        $this->assertServerException(
            OAuth2::ERROR_UNSUPPORTED_GRANT_TYPE,
            null,
            fn () => $this->token($this->bareStorage(), array(
                'grant_type' => 'urn:my:extension', 'client_id' => 'cid', 'client_secret' => 'cpass',
            ))
        );
    }

    public function testExtensionGrantRejectedByTheStorageIsAnInvalidGrant()
    {
        $storage = $this->createMock('OAuth2\IOAuth2GrantExtension');
        $storage->expects($this->any())->method('getClient')->willReturn(new OAuth2Client('cid', 'cpass'));
        $storage->expects($this->any())->method('checkClientCredentials')->willReturn(true);
        $storage->expects($this->any())->method('checkRestrictedGrantType')->willReturn(true);
        $storage->expects($this->any())->method('checkGrantExtension')->willReturn(false);

        $this->assertServerException(
            OAuth2::ERROR_INVALID_GRANT,
            null,
            fn () => $this->token($storage, array(
                'grant_type' => 'urn:my:extension', 'client_id' => 'cid', 'client_secret' => 'cpass',
            ))
        );
    }

// Authorize endpoint

    public function testAuthorizeRedirectsWhenTheResponseTypeIsUnsupportedByTheStorage()
    {
        $storage = $this->bareStorage(array('http://www.example.com/'));

        try {
            $this->authorize($storage, array(
                'client_id' => 'cid', 'response_type' => OAuth2::RESPONSE_TYPE_AUTH_CODE,
                'redirect_uri' => 'http://www.example.com/', 'state' => 'xyz',
            ));
            $this->fail('The expected OAuth2RedirectException was not thrown');
        } catch (OAuth2RedirectException $e) {
            $this->assertSame(OAuth2::ERROR_UNSUPPORTED_RESPONSE_TYPE, $e->getMessage());
            parse_str(parse_url($e->getResponseHeaders()['Location'], PHP_URL_QUERY), $params);
            $this->assertSame(OAuth2::ERROR_UNSUPPORTED_RESPONSE_TYPE, $params['error']);
            $this->assertSame('xyz', $params['state']);
        }
    }

    public function testAuthorizeRedirectsWhenAnUnknownResponseTypeIsRequested()
    {
        $stub = new OAuth2GrantCodeStub();
        $stub->addClient(new OAuth2Client('cid', 'cpass', array('http://www.example.com/')));

        try {
            $this->authorize($stub, array(
                'client_id' => 'cid', 'response_type' => 'carrier_pigeon', 'redirect_uri' => 'http://www.example.com/',
            ));
            $this->fail('The expected OAuth2RedirectException was not thrown');
        } catch (OAuth2RedirectException $e) {
            $this->assertSame(OAuth2::ERROR_UNSUPPORTED_RESPONSE_TYPE, $e->getMessage());
        }
    }

    public function testAuthorizeCanEnforceTheStateParameter()
    {
        $stub = new OAuth2GrantCodeStub();
        $stub->addClient(new OAuth2Client('cid', 'cpass', array('http://www.example.com/')));

        $oauth2 = new OAuth2($stub);
        $oauth2->setVariable(OAuth2::CONFIG_ENFORCE_STATE, true);

        try {
            $oauth2->finishClientAuthorization(true, null, new Request(array(
                'client_id' => 'cid', 'response_type' => OAuth2::RESPONSE_TYPE_AUTH_CODE,
                'redirect_uri' => 'http://www.example.com/',
            )));
            $this->fail('The expected OAuth2RedirectException was not thrown');
        } catch (OAuth2RedirectException $e) {
            $this->assertSame(OAuth2::ERROR_INVALID_REQUEST, $e->getMessage());
            $this->assertSame('The state parameter is required.', $e->getDescription());
        }
    }

    public function testAuthorizeFallsBackToTheSingleRegisteredRedirectUri()
    {
        $stub = new OAuth2GrantCodeStub();
        $stub->addClient(new OAuth2Client('cid', 'cpass', array('http://www.example.com/callback')));

        $oauth2 = new OAuth2($stub);
        // without this, an absent redirect_uri is an error rather than a fallback
        $oauth2->setVariable(OAuth2::CONFIG_ENFORCE_INPUT_REDIRECT, false);

        $response = $oauth2->finishClientAuthorization(true, null, new Request(array(
            'client_id' => 'cid', 'response_type' => OAuth2::RESPONSE_TYPE_AUTH_CODE,
        )));

        $this->assertStringStartsWith('http://www.example.com/callback?', $response->headers->get('Location'));
        $this->assertNotNull($stub->getLastAuthCode());
    }

    public function testAuthorizeRejectsAClientWithoutAnyRegisteredRedirectUri()
    {
        $stub = new OAuth2GrantCodeStub();
        $stub->addClient(new OAuth2Client('cid', 'cpass'));

        $oauth2 = new OAuth2($stub);
        $oauth2->setVariable(OAuth2::CONFIG_ENFORCE_INPUT_REDIRECT, false);

        $this->assertServerException(
            OAuth2::ERROR_REDIRECT_URI_MISMATCH,
            'No redirect URL was supplied or registered.',
            fn () => $oauth2->finishClientAuthorization(true, null, new Request(array(
                'client_id' => 'cid', 'response_type' => OAuth2::RESPONSE_TYPE_AUTH_CODE,
            )))
        );
    }

    public function testAuthorizeRejectsAnAmbiguousRedirectUri()
    {
        $stub = new OAuth2GrantCodeStub();
        $stub->addClient(new OAuth2Client('cid', 'cpass', array('http://a.example.com/', 'http://b.example.com/')));

        $oauth2 = new OAuth2($stub);
        $oauth2->setVariable(OAuth2::CONFIG_ENFORCE_INPUT_REDIRECT, false);

        $this->assertServerException(
            OAuth2::ERROR_REDIRECT_URI_MISMATCH,
            'No redirect URL was supplied and more than one is registered.',
            fn () => $oauth2->finishClientAuthorization(true, null, new Request(array(
                'client_id' => 'cid', 'response_type' => OAuth2::RESPONSE_TYPE_AUTH_CODE,
            )))
        );
    }

    public function testAuthorizeRejectsAMissingRedirectUriWhenItIsEnforced()
    {
        $stub = new OAuth2GrantCodeStub();
        $stub->addClient(new OAuth2Client('cid', 'cpass', array('http://www.example.com/')));

        $this->assertServerException(
            OAuth2::ERROR_REDIRECT_URI_MISMATCH,
            'The redirect URI is mandatory and was not supplied.',
            fn () => $this->authorize($stub, array('client_id' => 'cid', 'response_type' => OAuth2::RESPONSE_TYPE_AUTH_CODE))
        );
    }

    public function testAuthorizeRejectsAnUnknownClient()
    {
        $stub = new OAuth2GrantCodeStub();

        $this->assertServerException(
            OAuth2::ERROR_INVALID_CLIENT,
            'Unknown client',
            fn () => $this->authorize($stub, array('client_id' => 'ghost', 'response_type' => OAuth2::RESPONSE_TYPE_AUTH_CODE))
        );
    }

    public function testAuthorizeRequiresAClientId()
    {
        $stub = new OAuth2GrantCodeStub();

        $this->assertServerException(
            OAuth2::ERROR_INVALID_REQUEST,
            'No client id supplied',
            fn () => $this->authorize($stub, array('response_type' => OAuth2::RESPONSE_TYPE_AUTH_CODE))
        );
    }

// Utility methods

    private function storageWithClient(): OAuth2StorageStub
    {
        $stub = new OAuth2StorageStub();
        $stub->addClient(new OAuth2Client('cid', 'cpass'));
        $stub->setAllowedGrantTypes(array(
            OAuth2::GRANT_TYPE_AUTH_CODE, OAuth2::GRANT_TYPE_USER_CREDENTIALS, OAuth2::GRANT_TYPE_CLIENT_CREDENTIALS,
        ));

        return $stub;
    }

    /**
     * A storage implementing nothing beyond IOAuth2Storage: no grant is supported.
     */
    private function bareStorage(array $redirectUris = array())
    {
        $storage = $this->createMock('OAuth2\IOAuth2Storage');
        $storage->expects($this->any())->method('getClient')->willReturn(new OAuth2Client('cid', 'cpass', $redirectUris));
        $storage->expects($this->any())->method('checkClientCredentials')->willReturn(true);
        $storage->expects($this->any())->method('checkRestrictedGrantType')->willReturn(true);

        return $storage;
    }

    /**
     * @return \Symfony\Component\HttpFoundation\Response
     */
    private function token($storage, array $params)
    {
        return (new OAuth2($storage))->grantAccessToken(new Request($params));
    }

    /**
     * @return \Symfony\Component\HttpFoundation\Response
     */
    private function authorize($storage, array $query)
    {
        return (new OAuth2($storage))->finishClientAuthorization(true, null, new Request($query));
    }

    private function assertServerException(string $error, ?string $description, callable $call): void
    {
        try {
            $call();
            $this->fail('The expected OAuth2ServerException was not thrown');
        } catch (OAuth2ServerException $e) {
            $this->assertSame($error, $e->getMessage());
            if ($description !== null) {
                $this->assertSame($description, $e->getDescription());
            }
        }
    }
}
