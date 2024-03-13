<?php

namespace OAuth2\Model;

class OAuth2Token implements IOAuth2Token
{
    private ?string $clientId;

    private ?string $token;

    private ?int $expiresAt;

    private ?string $scope;

    private mixed $data;

    public function __construct(
        ?string $clientId,
        ?string $token,
        ?int $expiresAt = null,
        ?string $scope = null,
        mixed $data = null,
    ) {
        $this->setClientId($clientId);
        $this->setToken($token);
        $this->setExpiresAt($expiresAt);
        $this->setScope($scope);
        $this->setData($data);
    }

    public function setClientId(?string $id): void
    {
        $this->clientId = $id;
    }

    public function getClientId(): ?string
    {
        return $this->clientId;
    }

    public function setExpiresAt(?int $timestamp): void
    {
        $this->expiresAt = $timestamp;
    }

    public function getExpiresIn(): int
    {
        if ($this->expiresAt) {
            return $this->expiresAt - time();
        }

        return PHP_INT_MAX;
    }

    public function hasExpired(): bool
    {
        return time() > $this->expiresAt;
    }

    public function setToken(?string $token): void
    {
        $this->token = $token;
    }

    public function getToken(): ?string
    {
        return $this->token;
    }

    public function setScope(?string $scope): void
    {
        $this->scope = $scope;
    }

    public function getScope(): string|null
    {
        return $this->scope;
    }

    public function setData(mixed $data): void
    {
        $this->data = $data;
    }

    public function getData(): mixed
    {
        return $this->data;
    }
}
