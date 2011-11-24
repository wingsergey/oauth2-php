<?php

namespace OAuth2\Model;

interface IOAuth2Client {

    public function getId();
    public function getRedirectUris();
}

