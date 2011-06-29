<?php

/**
 * Static test suite.
 */
class OAuth2Suite extends PHPUnit_Framework_TestSuite {
  
  /**
   * Constructs the test suite handler.
   */
  public function __construct() {
    $this->setName ( 'OAuth2Suite' );
  }
  
  /**
   * Creates the suite.
   */
  public static function suite() {
    return new self ();
  }
}

