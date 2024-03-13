<?php

namespace OAuth2;

use OAuth2\Model\IOAuth2Client;

/**
 * Storage engines that support the "Client Credentials" grant type should implement this interface
 *
 * @author Dave Rochwerger <catch.dave@gmail.com>
 *
 * @see    http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.4
 */
interface IOAuth2GrantClient extends IOAuth2Storage
{
    /**
     * Required for OAuth2::GRANT_TYPE_CLIENT_CREDENTIALS.
     *
     * @param IOAuth2Client $client       The client for which to check credentials.
     * @param string $clientSecret (optional) If a secret is required, check that they've given the right one.
     *
     * @return bool Returns true if the client credentials are valid, and MUST return false if they aren't.
     * When using "client credentials" grant mechanism and you want to
     * verify the scope of a user's access, return an associative array
     * with the scope values as below. We'll check the scope you provide
     * against the requested scope before providing an access token:
     * 
     * @return bool
     *
     * @see     http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.4.2
     *
     * @ingroup oauth2_section_4
     */
    public function checkClientCredentialsGrant(IOAuth2Client $client, string $clientSecret): bool;
}
