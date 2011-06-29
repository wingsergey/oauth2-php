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

    foreach (glob(__DIR__.'/*Test.php') as $filename) {
      require_once($filename);
      $class = basename($filename, '.php');
    //  $this->addTest(new $class());
      $this->addTestSuite($class);
    }
  }
  
  /**
   * Creates the suite.
   */
  public static function suite() {
    return new self ();
  }
}

