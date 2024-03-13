<?php

namespace OAuth2\Tests\Fixtures;

use FOS\OAuthServerBundle\Model\TokenInterface;
use OAuth2\Model\IOAuth2AccessToken;
use OAuth2\Model\IOAuth2RefreshToken;
use OAuth2\OAuth2;
use OAuth2\Model\IOAuth2Client;
use OAuth2\Model\OAuth2AccessToken;
use OAuth2\Model\OAuth2RefreshToken;
use OAuth2\IOAuth2Storage;
use OAuth2\IOAuth2GrantClient;
use OAuth2\IOAuth2RefreshTokens;

/**
 * IOAuth2Storage stub for testing
 */
class OAuth2StorageStub implements IOAuth2Storage, IOAuth2GrantClient, IOAuth2RefreshTokens
{
    private array $clients = array();
    private array $accessTokens = array();
    private array $refreshTokens = array();
    private array $allowedGrantTypes = array(OAuth2::GRANT_TYPE_AUTH_CODE);

    public function addClient(IOAuth2Client $client): void
    {
        $this->clients[$client->getPublicId()] = $client;
    }

    public function getClient(string $clientId): ?IOAuth2Client
    {
        if (isset($this->clients[$clientId])) {
            return $this->clients[$clientId];
        }
        return null;
    }

    public function getClients(): array
    {
        return $this->clients;
    }

    public function checkClientCredentials(IOAuth2Client $client, string $clientSecret = null): bool
    {
        return $client->checkSecret($clientSecret);
    }

    public function checkClientCredentialsGrant(IOAuth2Client $client, string $clientSecret): bool
    {
        return $this->checkClientCredentials($client, $clientSecret);
    }

    public function createAccessToken(
        string $oauth_token,
        IOAuth2Client $client,
        mixed $data,
        int $expires,
        string $scope = null
    ): IOAuth2AccessToken {
        $token = new OAuth2AccessToken($client->getPublicId(), $oauth_token, $expires, $scope, $data);

        $this->accessTokens[$oauth_token] = $token;

        return $token;
    }

    public function getAccessToken(string $oauthToken): ?IOAuth2AccessToken
    {
        if (isset($this->accessTokens[$oauthToken])) {
            return $this->accessTokens[$oauthToken];
        }
        return null;
    }

    public function getAccessTokens(): array
    {
        return $this->accessTokens;
    }

    public function getLastAccessToken(): IOAuth2AccessToken
    {
        return end($this->accessTokens);
    }

    public function setAllowedGrantTypes(array $types): void
    {
        $this->allowedGrantTypes = $types;
    }

    public function checkRestrictedGrantType(IOAuth2Client $client, string $grantType): bool
    {
        return in_array($grantType, $this->allowedGrantTypes);
    }

    public function getRefreshToken(string $refreshToken): IOAuth2RefreshToken
    {
        if (isset($this->refreshTokens[$refreshToken])) {
            return $this->refreshTokens[$refreshToken];
        }
    }

    public function createRefreshToken(
        string $refreshToken,
        IOAuth2Client $client,
        mixed $data,
        int $expires,
        string $scope = null
    ): IOAuth2RefreshToken {
        $token = new OAuth2RefreshToken($client->getPublicId(), $refreshToken, $expires, $scope, $data);

        $this->refreshToken[$refreshToken] = $token;
        
        return $token;
    }

    public function unsetRefreshToken(string $refreshToken): void
    {
        if (isset($this->refreshTokens[$refreshToken])) {
            unset($this->refreshTokens[$refreshToken]);
        }
    }
}
