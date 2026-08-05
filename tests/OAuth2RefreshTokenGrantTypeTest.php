<?php

use OAuth2\OAuth2;
use OAuth2\OAuth2ServerException;
use OAuth2\Model\OAuth2Client;
use OAuth2\Tests\Fixtures\OAuth2StorageStub;
use Symfony\Component\HttpFoundation\Request;

/**
 * Covers the refresh_token grant (RFC 6749 section 6), including the rotation of the
 * refresh token that was presented.
 */
class OAuth2RefreshTokenGrantTypeTest extends \PHPUnit\Framework\TestCase
{
    public function testRefreshTokenGrantIssuesANewAccessToken()
    {
        $data = new \stdClass();
        $stub = $this->createStorage();
        $stub->createRefreshToken('my_refresh_token', $stub->getClient('cid'), $data, time() + 600, 'scope1');

        $response = $this->grant($stub, 'my_refresh_token');
        $payload = json_decode($response->getContent(), true);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertNotEmpty($payload['access_token']);
        $this->assertSame('bearer', $payload['token_type']);
        // scope and data are carried over from the presented refresh token
        $this->assertSame('scope1', $payload['scope']);
        $accessToken = $stub->getLastAccessToken();
        $this->assertSame('cid', $accessToken->getClientId());
        $this->assertSame($data, $accessToken->getData());
        $this->assertSame('scope1', $accessToken->getScope());
    }

    public function testRefreshTokenIsRotated()
    {
        $stub = $this->createStorage();
        $stub->createRefreshToken('my_refresh_token', $stub->getClient('cid'), null, time() + 600);

        $payload = json_decode($this->grant($stub, 'my_refresh_token')->getContent(), true);

        // a brand new refresh token is handed out...
        $this->assertArrayHasKey('refresh_token', $payload);
        $this->assertNotSame('my_refresh_token', $payload['refresh_token']);
        $this->assertNotNull($stub->getRefreshToken($payload['refresh_token']));
        // ...and the one that was just spent is revoked
        $this->assertNull($stub->getRefreshToken('my_refresh_token'));
    }

    public function testRefreshTokenGrantRejectsAMissingToken()
    {
        $stub = $this->createStorage();

        try {
            $this->grant($stub, null);
            $this->fail('The expected OAuth2ServerException was not thrown');
        } catch (OAuth2ServerException $e) {
            $this->assertSame(OAuth2::ERROR_INVALID_REQUEST, $e->getMessage());
            $this->assertSame('No "refresh_token" parameter found', $e->getDescription());
        }
    }

    public function testRefreshTokenGrantRejectsAnUnknownToken()
    {
        $stub = $this->createStorage();

        try {
            $this->grant($stub, 'never_issued');
            $this->fail('The expected OAuth2ServerException was not thrown');
        } catch (OAuth2ServerException $e) {
            $this->assertSame(OAuth2::ERROR_INVALID_GRANT, $e->getMessage());
            $this->assertSame('Invalid refresh token', $e->getDescription());
        }
    }

    public function testRefreshTokenGrantRejectsATokenIssuedToAnotherClient()
    {
        $stub = $this->createStorage();
        $other = new OAuth2Client('other_client', 'other_pass');
        $stub->addClient($other);
        $stub->createRefreshToken('someone_elses_token', $other, null, time() + 600);

        try {
            $this->grant($stub, 'someone_elses_token');
            $this->fail('The expected OAuth2ServerException was not thrown');
        } catch (OAuth2ServerException $e) {
            $this->assertSame(OAuth2::ERROR_INVALID_GRANT, $e->getMessage());
            $this->assertSame('Invalid refresh token', $e->getDescription());
        }

        // the other client's token must survive the failed attempt
        $this->assertNotNull($stub->getRefreshToken('someone_elses_token'));
    }

    public function testRefreshTokenGrantRejectsAnExpiredToken()
    {
        $stub = $this->createStorage();
        $stub->createRefreshToken('stale_token', $stub->getClient('cid'), null, time() - 1);

        try {
            $this->grant($stub, 'stale_token');
            $this->fail('The expected OAuth2ServerException was not thrown');
        } catch (OAuth2ServerException $e) {
            $this->assertSame(OAuth2::ERROR_INVALID_GRANT, $e->getMessage());
            $this->assertSame('Refresh token has expired', $e->getDescription());
        }

        // a rejected token is left alone, not silently revoked
        $this->assertNotNull($stub->getRefreshToken('stale_token'));
    }

    public function testRefreshTokenGrantIsUnsupportedWhenTheStorageCannotStoreThem()
    {
        // the base stub does implement IOAuth2RefreshTokens, so a storage that genuinely
        // cannot refresh has to be built from the bare interface
        $storage = $this->createMock('OAuth2\IOAuth2Storage');
        $storage->expects($this->any())->method('getClient')->willReturn(new OAuth2Client('cid', 'cpass'));
        $storage->expects($this->any())->method('checkClientCredentials')->willReturn(true);
        $storage->expects($this->any())->method('checkRestrictedGrantType')->willReturn(true);

        try {
            (new OAuth2($storage))->grantAccessToken(new Request(array(
                'grant_type' => OAuth2::GRANT_TYPE_REFRESH_TOKEN,
                'client_id' => 'cid',
                'client_secret' => 'cpass',
                'refresh_token' => 'whatever',
            )));
            $this->fail('The expected OAuth2ServerException was not thrown');
        } catch (OAuth2ServerException $e) {
            $this->assertSame(OAuth2::ERROR_UNSUPPORTED_GRANT_TYPE, $e->getMessage());
        }
    }

    public function testClientCredentialsGrantIssuesNoRefreshToken()
    {
        // unlike the refresh_token grant, client_credentials opts out of refresh tokens
        $stub = new OAuth2StorageStub();
        $stub->addClient(new OAuth2Client('cid', 'cpass'));
        $stub->setAllowedGrantTypes(array(OAuth2::GRANT_TYPE_CLIENT_CREDENTIALS));

        $response = (new OAuth2($stub))->grantAccessToken(new Request(array(
            'grant_type' => OAuth2::GRANT_TYPE_CLIENT_CREDENTIALS,
            'client_id' => 'cid',
            'client_secret' => 'cpass',
        )));
        $payload = json_decode($response->getContent(), true);

        $this->assertArrayHasKey('access_token', $payload);
        $this->assertArrayNotHasKey('refresh_token', $payload);
    }

// Utility methods

    /**
     * A storage that supports the refresh_token grant.
     */
    private function createStorage(): OAuth2StorageStub
    {
        $stub = new OAuth2StorageStub();
        $stub->addClient(new OAuth2Client('cid', 'cpass'));
        $stub->setAllowedGrantTypes(array(OAuth2::GRANT_TYPE_REFRESH_TOKEN));

        return $stub;
    }

    /**
     * @return \Symfony\Component\HttpFoundation\Response
     */
    private function grant(OAuth2StorageStub $stub, ?string $refreshToken)
    {
        $params = array(
            'grant_type' => OAuth2::GRANT_TYPE_REFRESH_TOKEN,
            'client_id' => 'cid',
            'client_secret' => 'cpass',
        );
        if ($refreshToken !== null) {
            $params['refresh_token'] = $refreshToken;
        }

        return (new OAuth2($stub))->grantAccessToken(new Request($params));
    }
}
