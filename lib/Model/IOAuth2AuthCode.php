<?php

namespace OAuth2\Model;

interface IOAuth2AuthCode extends IOAuth2Token
{
    /**
     * @return string
     */
    public function getRedirectUri();

    /**
     * The OpenID Connect "nonce" supplied on the authorization request, if any.
     *
     * It is bound to the authorization code so that it can be replayed in the
     * id_token issued on the (back-channel) token request.
     *
     * @return null|string
     */
    public function getNonce();

    /**
     * The OpenID Connect "auth_time": Unix timestamp of the end-user authentication that
     * led to this authorization code.
     *
     * Server-side value — it is stamped by the storage when the code is created, never
     * taken from the authorization request, and read back on the token request.
     *
     * @return null|int
     */
    public function getAuthTime();
}
