<?php

namespace OAuth2\Model;

class OAuth2AuthCode extends OAuth2Token implements IOAuth2AuthCode
{
    /**
     * @var null|string
     */
    private $redirectUri;

    /**
     * @var null|string
     */
    private $nonce;

    /**
     * @var null|int
     */
    private $authTime;

    /**
     * @param string       $clientId
     * @param string       $token
     * @param null|integer $expiresAt
     * @param null|string  $scope
     * @param mixed        $data
     * @param null|string  $redirectUri
     * @param null|string  $nonce
     * @param null|int     $authTime
     */
    public function __construct($clientId, $token, $expiresAt = null, $scope = null, $data = null, $redirectUri = null, $nonce = null, $authTime = null)
    {
        parent::__construct($clientId, $token, $expiresAt, $scope, $data);
        $this->setRedirectUri($redirectUri);
        $this->setNonce($nonce);
        $this->setAuthTime($authTime);
    }

    /**
     * @param null|string $uri
     */
    public function setRedirectUri($uri)
    {
        $this->redirectUri = $uri;
    }

    /**
     * {@inheritdoc}
     */
    public function getRedirectUri()
    {
        return $this->redirectUri;
    }

    /**
     * @param null|string $nonce
     */
    public function setNonce($nonce)
    {
        $this->nonce = $nonce;
    }

    /**
     * {@inheritdoc}
     */
    public function getNonce()
    {
        return $this->nonce;
    }

    /**
     * @param null|int $authTime
     */
    public function setAuthTime($authTime)
    {
        $this->authTime = $authTime;
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthTime()
    {
        return $this->authTime;
    }
}
