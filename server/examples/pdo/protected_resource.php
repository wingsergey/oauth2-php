<?php

/**
 * @file
 * Sample protected resource.
 *
 * Obviously not production-ready code, just simple and to the point.
 *
 * In reality, you'd probably use a nifty framework to handle most of the crud for you.
 */

require "lib/PDOOAuth2.php";

$token = isset($_GET[OAUTH2_TOKEN_PARAM_NAME]) ? $_GET[OAUTH2_TOKEN_PARAM_NAME] : null;
$oauth = new OAuth2(new OAuth2StoragePDO());
$oauth->verifyAccessToken($token);

// With a particular scope, you'd do:
// $oauth->verifyAccessToken("scope_name");

?>

<html>
  <head>
    <title>Hello!</title>
  </head>
  <body>
    <p>This is a secret.</p>
  </body>
</html>
