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
    protected array $header;

    /**
     * @param string $httpCode
     * @param string $tokenType
     * @param string $realm
     * @param string $error            The "error" attribute is used to provide the client with the reason why the access request was declined.
     * @param string|null $errorDescription (optional) Human-readable text containing additional information, used to assist in the understanding and resolution of the error occurred.
     * @param string|null $scope            (optional) A space-delimited list of scope values indicating the required scope of the access token for accessing the requested resource.
     */
    public function __construct(
        string $httpCode,
        string $tokenType,
        string $realm,
        string $error,
        ?string $errorDescription = null,
        ?string $scope = null
    ) {
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

    public function getResponseHeaders(): array
    {
        return $this->header + parent::getResponseHeaders();
    }

    /**
     * Adds quotes around $text
     */
    private function quote(string $text): string
    {
        // https://tools.ietf.org/html/draft-ietf-httpbis-p1-messaging-17#section-3.2.3
        $text = preg_replace(
            '~
                        [^
                            \x21-\x7E
                            \x80-\xFF
                            \ \t
                        ]
                        ~x',
            '',
            $text
        );

        $text = addcslashes($text, '"\\');

        return '"' . $text . '"';
    }
}
