<?php

namespace OAuth2\Tests\Fixtures;

use OAuth2\Model\IOAuth2AuthCode;
use OAuth2\Model\IOAuth2Client;
use OAuth2\Model\OAuth2AuthCode;
use OAuth2\IOAuth2GrantCode;

class OAuth2GrantCodeStub extends OAuth2StorageStub implements IOAuth2GrantCode
{
    private array $authCodes;

    public function getAuthCode(string $code): ?IOAuth2AuthCode
    {
        if (isset($this->authCodes[$code])) {
            return $this->authCodes[$code];
        }
        return null;
    }

    public function getAuthCodes(): array
    {
        return $this->authCodes;
    }

    public function getLastAuthCode(): IOAuth2AuthCode
    {
        return end($this->authCodes);
    }

    public function createAuthCode(
        string $code,
        IOAuth2Client $client,
        mixed $data,
        string $redirectUri,
        int $expires,
        string $scope = null
    ): IOAuth2AuthCode {
        $token = new OAuth2AuthCode($client->getPublicId(), $code, $expires, $scope, $data, $redirectUri);
        $this->authCodes[$code] = $token;
        
        return $token;
    }

    public function markAuthCodeAsUsed(string $code): void
    {
        if (isset($this->authCodes[$code])) {
            unset($this->authCodes[$code]);
        }
    }
}
