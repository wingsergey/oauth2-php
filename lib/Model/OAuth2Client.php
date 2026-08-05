<?php

namespace OAuth2\Model;

class OAuth2Client implements IOAuth2Client
{
    /**
     * @var string
     */
    private $id;

    /**
     * @var array<int, string>
     */
    private $redirectUris;

    /**
     * @var null|string
     */
    private $secret;

    /**
     * @param string             $id
     * @param null|string        $secret
     * @param array<int, string> $redirectUris
     */
    public function __construct($id, $secret = null, array $redirectUris = array())
    {
        $this->setPublicId($id);
        $this->setSecret($secret);
        $this->setRedirectUris($redirectUris);
    }

    /**
     * @param string $id
     *
     * @return void
     */
    public function setPublicId($id)
    {
        $this->id = $id;
    }

    /**
     * {@inheritdoc}
     */
    public function getPublicId()
    {
        return $this->id;
    }

    /**
     * @param string|null $secret
     *
     * @return void
     */
    public function setSecret($secret)
    {
        $this->secret = $secret;
    }

    /**
     * @param mixed $secret
     *
     * @return boolean
     */
    public function checkSecret($secret)
    {
        return $this->secret === null || $secret === $this->secret;
    }

    /**
     * @param array<int, string> $redirectUris
     *
     * @return void
     */
    public function setRedirectUris(array $redirectUris)
    {
        $this->redirectUris = $redirectUris;
    }

    /**
     * {@inheritdoc}
     */
    public function getRedirectUris()
    {
        return $this->redirectUris;
    }
}
