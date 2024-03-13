<?php

namespace OAuth2\Model;

interface IOAuth2Client
{
    /**
     * @return string
     */
    public function getPublicId(): string;

    /**
     * @return array
     */
    public function getRedirectUris(): array;
}
