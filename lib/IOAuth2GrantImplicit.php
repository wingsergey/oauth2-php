<?php
/**
 * Storage engines that support the "Implicit"
 * grant type should implement this interface
 * 
 * @author Dave Rochwerger <catch.dave@gmail.com>
 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-16#section-4.2
 */
interface IOAuth2GrantImplicit {

  /**
   * The Implicit grant type supports a response type of "token". 
   * 
   * @var string
   * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-16#section-2.1
   * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-16#section-4.2.1
   */
  const RESPONSE_TYPE_TOKEN = OAuth2::RESPONSE_TYPE_ACCESS_TOKEN;
}