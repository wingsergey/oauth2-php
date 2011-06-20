<?php

/**
 * @file
 * Sample OAuth2 Library PDO DB Implementation.
 * 
 * Simply pass in a configured PDO class, eg:
 *   new PDOOAuth2( new PDO('mysql:dbname=mydb;host=localhost', 'user', 'pass') );
 */

include '../../../lib/OAuth2.inc';
include '../../../lib/IOAuth2Storage.php';

/**
 * PDO storage engine for the OAuth2 Library.
 */
class PDOOAuth2 implements IOAuth2Storage {

  /**
   * Change this to something unique for your system
   * @var string
   */
  const SALT = 'CHANGE_ME!';
  
  /**@#+
   * Centralized table names
   * 
   * @var string
   */
  const TABLE_CLIENTS = 'clients';
  const TABLE_CODES   = 'auth_codes';
  const TABLE_TOKENS  = 'access_tokens';
  const TABLE_REFRESH = 'refresh_tokens';
  /**@#-*/
  
  /**
   * @var PDO
   */
  private $db;

  /**
   * Implements OAuth2::__construct().
   */
  public function __construct(PDO $db) {

    try {
      $this->db = $db;
    } catch (PDOException $e) {
      die('Connection failed: '. $e->getMessage());
    }
  }

  /**
   * Release DB connection during destruct.
   */
  function __destruct() {
    $this->db = NULL; // Release db connection
  }

  /**
   * Handle PDO exceptional cases.
   */
  private function handleException($e) {
    echo 'Database error: '. $e->getMessage();
    exit;
  }

  /**
   * Little helper function to add a new client to the database.
   *
   * Do NOT use this in production! This sample code stores the secret
   * in plaintext!
   *
   * @param $client_id
   *   Client identifier to be stored.
   * @param $client_secret
   *   Client secret to be stored.
   * @param $redirect_uri
   *   Redirect URI to be stored.
   */
  public function addClient($client_id, $client_secret, $redirect_uri) {
    try {
      $client_secret = $this->hash($client_id, $client_secret);
      
      $sql = 'INSERT INTO '. TABLE_CLIENTS .' (client_id, client_secret, redirect_uri) VALUES (:client_id, :client_secret, :redirect_uri)';
      $stmt = $this->db->prepare($sql);
      $stmt->bindParam(':client_id', $client_id, PDO::PARAM_STR);
      $stmt->bindParam(':client_secret', $client_secret, PDO::PARAM_STR);
      $stmt->bindParam(':redirect_uri', $redirect_uri, PDO::PARAM_STR);
      $stmt->execute();
    } catch (PDOException $e) {
      $this->handleException($e);
    }
  }

  /**
   * Implements IOAuth2Storage::checkClientCredentials().
   *
   */
  public function checkClientCredentials($client_id, $client_secret = NULL) {
    try {
      $sql = 'SELECT client_secret FROM clients WHERE client_id = :client_id';
      $stmt = $this->db->prepare($sql);
      $stmt->bindParam(':client_id', $client_id, PDO::PARAM_STR);
      $stmt->execute();

      $result = $stmt->fetch(PDO::FETCH_ASSOC);

      if ($client_secret === NULL)
          return $result !== FALSE;

      return $result['client_secret'] == $this->hash($client_id, $client_secret);
    } catch (PDOException $e) {
      $this->handleException($e);
    }
  }

  /**
   * Implements IOAuth2Storage::getRedirectUri().
   */
  public function getClientDetails($client_id) {
    try {
      $sql = 'SELECT redirect_uri FROM clients WHERE client_id = :client_id';
      $stmt = $this->db->prepare($sql);
      $stmt->bindParam(':client_id', $client_id, PDO::PARAM_STR);
      $stmt->execute();

      $result = $stmt->fetch(PDO::FETCH_ASSOC);

      if ($result === FALSE)
          return FALSE;

      return isset($result['redirect_uri']) && $result['redirect_uri'] ? $result['redirect_uri'] : NULL;
    } catch (PDOException $e) {
      $this->handleException($e);
    }
  }

  /**
   * Implements IOAuth2Storage::getAccessToken().
   */
  public function getAccessToken($oauth_token) {
  	return $this->getToken($oauth_token, FALSE);
  }

  /**
   * Implements IOAuth2Storage::setAccessToken().
   */
  public function setAccessToken($oauth_token, $client_id, $user_id, $expires, $scope = NULL) {
  	$this->setToken($oauth_token, $client_id, $user_id, $expires, $scope, FALSE);
  }
  
  /**
   * @see IOAuth2Storage::getRefreshToken()
   */
  public function getRefreshToken($refresh_token) {
    return $this->getToken($refresh_token, TRUE);
  }
  
  /**
   * @see IOAuth2Storage::setRefreshToken()
   */
  public function setRefreshToken($refresh_token, $client_id, $user_id, $expires, $scope = NULL) {
    return $this->setToken($refresh_token, $client_id, $user_id, $expires, $scope, TRUE);
  }
  
  /**
   * @see IOAuth2Storage::unsetRefreshToken()
   */
  public function unsetRefreshToken($refresh_token) {
    try {
	  $this->db->delete(self::TABLE_TOKENS, array('oauth_token' => $refresh_token, 'is_refresh' => 1));
    } catch (PDOException $e) {
	  $this->handleException($e);
    }
  }

  /**
   * Implements IOAuth2Storage::getSupportedGrantTypes().
   */
  public function getSupportedAuthResponseTypes() {
		return array(OAUTH2_AUTH_RESPONSE_TYPE_AUTH_CODE, OAUTH2_AUTH_RESPONSE_TYPE_ACCESS_TOKEN);
	}

  /**
   * Implements IOAuth2Storage::getAuthCode().
   */
  public function getAuthCode($code) {
    try {
      $sql = 'SELECT code, client_id, user_id, redirect_uri, expires, scope FROM '. self::TABLE_CODES .'auth_codes WHERE code = :code';
      $stmt = $this->db->prepare($sql);
      $stmt->bindParam(':code', $code, PDO::PARAM_STR);
      $stmt->execute();

      $result = $stmt->fetch(PDO::FETCH_ASSOC);

      return $result !== FALSE ? $result : NULL;
    } catch (PDOException $e) {
      $this->handleException($e);
    }
  }

  /**
   * Implements IOAuth2Storage::setAuthCode().
   */
  public function setAuthCode($code, $client_id, $user_id, $redirect_uri, $expires, $scope = NULL) {
    try {
      $sql = 'INSERT INTO '. self::TABLE_CLIENTS .' (code, client_id, user_id, redirect_uri, expires, scope) VALUES (:code, :client_id, :user_id, :redirect_uri, :expires, :scope)';
      $stmt = $this->db->prepare($sql);
      $stmt->bindParam(':code', $code, PDO::PARAM_STR);
      $stmt->bindParam(':client_id', $client_id, PDO::PARAM_STR);
      $stmt->bindParam(':user_id', $user_id, PDO::PARAM_STR);
      $stmt->bindParam(':redirect_uri', $redirect_uri, PDO::PARAM_STR);
      $stmt->bindParam(':expires', $expires, PDO::PARAM_INT);
      $stmt->bindParam(':scope', $scope, PDO::PARAM_STR);

      $stmt->execute();
    } catch (PDOException $e) {
      $this->handleException($e);
    }
  }
  
  /**
   * @see IOAuth2Storage::checkUserCredentials()
   */
  public function checkUserCredentials($client_id, $username, $password) {
  	return NULL; // Not implemented
  }
  
  /**
   * @see IOAuth2Storage::checkNoneAccess()
   */
  public function checkNoneAccess($client_id) {
  	return NULL; // Not implemented
  }
  
  /**
   * @see IOAuth2Storage::checkAssertion()
   */
  public function checkAssertion($client_id, $assertion_type, $assertion) {
  	return NULL; // Not implemented
  }
  
  /**
   * Creates a refresh or access token
   * 
   * @param string $oauth_token
   * @param string $client_id
   * @param mixed $user_id
   * @param int $expires
   * @param string $scope
   * @param bool $isRefresh
   */
  protected function setToken($oauth_token, $client_id, $user_id, $expires, $scope, $isRefresh = TRUE) {
  	$tableName = $isRefresh ? self::TABLE_REFRESH :  self::TABLE_TOKENS;
  	
    try {
      $sql = 'INSERT INTO '.$tableName.'tokens (oauth_token, client_id, user_id, expires, scope) VALUES (:oauth_token, :client_id, :user_id, :expires, :scope)';
      $stmt = $this->db->prepare($sql);
      $stmt->bindParam(':oauth_token', $oauth_token, PDO::PARAM_STR);
      $stmt->bindParam(':client_id', $client_id, PDO::PARAM_STR);
      $stmt->bindParam(':user_id', $user_id, PDO::PARAM_STR);
      $stmt->bindParam(':expires', $expires, PDO::PARAM_INT);
      $stmt->bindParam(':scope', $scope, PDO::PARAM_STR);

      $stmt->execute();
    } catch (PDOException $e) {
      $this->handleException($e);
    }
  }
  
  /**
   * Change/override this to whatever your own password hashing method is.
   * 
   * @param string $secret
   * @return string
   */
  protected function hash($client_id, $client_secret) {
  	return hash('blowfish', $client_id . $client_secret . self::SALT);
  }
}
