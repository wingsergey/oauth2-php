<?php

namespace OAuth2\Model;

/**
 * An OAuth2 client, as known by the authorization server.
 *
 * This contract is deliberately framework-agnostic: a client is not a security
 * identity. Integrations that need to expose a client as a Symfony user should
 * add UserInterface on their own client contract instead.
 */
interface IOAuth2Client
{
    /**
     * @return string
     */
    public function getPublicId();

    /**
     * @return array
     */
    public function getRedirectUris();
}
