<?php

namespace OAuth2\Model;

interface IOAuth2Token
{
    public function getClientId(): ?string;

    public function getExpiresIn(): int;

    public function hasExpired(): bool;

    public function getToken(): ?string;

    public function getScope(): string|null;

    public function getData(): mixed;
}
