<?php

namespace OAuth2;

use OAuth2\Model\IOAuth2Client;

class OAuthTokenGrantedEvent
{
    public const NAME = 'oauth_server.token_granted';

    public function __construct(
        private array         $token,
        private IOAuth2Client $client,
        private mixed         $user,
        private ?string       $scope,
    ) {}

    public function getToken(): array            { return $this->token; }
    public function setToken(array $token): void { $this->token = $token; }
    public function getClient(): IOAuth2Client   { return $this->client; }
    public function getUser(): mixed             { return $this->user; }
    public function getScope(): ?string          { return $this->scope; }
}