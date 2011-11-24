<?php

namespace OAuth2\Model;

class OAuth2Client implements IOAuth2Client {

    private $id;

    public function __construct($id) {
        $this->setId($id);
    }

    public function setId($id) {
        $this->id = $id;
    }

    public function getId() {
        return $this->id;
    }
}

