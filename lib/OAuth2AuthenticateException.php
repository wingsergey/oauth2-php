<?php

namespace OAuth2;

/**
 * Send an error header with the given realm and an error, if provided.
 * Suitable for the bearer token type.
 *
 * @see     http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-04#section-2.4
 *
 * @ingroup oauth2_error
 */
class OAuth2AuthenticateException extends OAuth2ServerException
{
    /**
     * @var array<string, string>
     */
    protected $header;

    /**
     * @param int    $httpCode
     * @param string $tokenType
     * @param string $realm
     * @param string $error            The "error" attribute is used to provide the client with the reason why the access request was declined.
     * @param string $errorDescription (optional) Human-readable text containing additional information, used to assist in the understanding and resolution of the error occurred.
     * @param string $scope            (optional) A space-delimited list of scope values indicating the required scope of the access token for accessing the requested resource.
     */
    public function __construct($httpCode, $tokenType, $realm, $error, $errorDescription = null, $scope = null)
    {
        parent::__construct($httpCode, $error, $errorDescription);

        if ($scope) {
            $this->errorData['scope'] = $scope;
        }

        // Build header
        $header = sprintf('%s realm=%s', ucwords($tokenType), $this->quote($realm));
        foreach ($this->errorData as $key => $value) {
            $header .= sprintf(', %s=%s', $key, $this->quote($value));
        }

        $this->header = array('WWW-Authenticate' => $header);
    }

    /**
     * @return array<string, string>
     */
    public function getResponseHeaders()
    {
        return $this->header + parent::getResponseHeaders();
    }

    /**
     * Adds quotes around $text
     *
     * @param null|string $text A null error_description is a normal case, it must quote as "".
     *
     * @return string
     */
    private function quote($text)
    {
        $text = (string) $text;

        // Keep only what a quoted-string may hold: printable ASCII, obs-text, SP and HTAB.
        // https://tools.ietf.org/html/draft-ietf-httpbis-p1-messaging-17#section-3.2.3
        //
        // Written without the /x modifier on purpose: PCRE does not ignore whitespace
        // inside a character class, so an indented pattern would silently add LF, CR and
        // SP to the negated class and let them through into the header.
        $text = (string) preg_replace('~[^\x21-\x7E\x80-\xFF \t]~', '', $text);

        $text = addcslashes($text, '"\\');

        return '"' . $text . '"';
    }
}
