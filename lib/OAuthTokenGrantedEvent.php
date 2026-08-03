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
        private ?string       $nonce = null,
        private ?int          $authTime = null,
    ) {}

    public function getToken(): array            { return $this->token; }
    public function setToken(array $token): void { $this->token = $token; }
    public function getClient(): IOAuth2Client   { return $this->client; }
    public function getUser(): mixed             { return $this->user; }
    public function getScope(): ?string          { return $this->scope; }

    /**
     * OpenID Connect nonce bound to the authorization code that was exchanged, if any.
     * Always null for grant types that do not involve an authorization code.
     */
    public function getNonce(): ?string          { return $this->nonce; }

    /**
     * Unix timestamp of the end-user authentication behind the exchanged authorization code,
     * as stamped by the storage. Null when unknown or for code-less grant types.
     */
    public function getAuthTime(): ?int          { return $this->authTime; }
}