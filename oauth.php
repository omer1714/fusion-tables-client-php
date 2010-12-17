<?php

include_once "oauth-php/library/OAuthStore.php";
include_once "oauth-php/library/OAuthRequester.php";

define('SCOPE', 'http://www.google.com/fusiontables/api/query');
define('SERVER_URI', 'https://www.google.com');
define('GOOGLE_OAUTH_REQUEST_TOKEN_API', 'https://www.google.com/accounts/OAuthGetRequestToken');
define('GOOGLE_OAUTH_ACCESS_TOKEN_API', 'https://www.google.com/accounts/OAuthGetAccessToken');
define('GOOGLE_OAUTH_AUTHORIZE_API', 'https://www.google.com/accounts/OAuthAuthorizeToken');


class OAuthClient {

  public static function storeInstance($consumer_key, $consumer_secret, $store_type="MySQL", $extra_options=array()) {
    $options = array(
	    'consumer_key' => $consumer_key, 
	    'consumer_secret' => $consumer_secret,
	    'signature_methods' => array('HMAC-SHA1', 'PLAINTEXT'),
	    'server_uri' =>  SERVER_URI,
	    'request_token_uri' =>  GOOGLE_OAUTH_REQUEST_TOKEN_API,
	    'authorize_uri' =>  GOOGLE_OAUTH_AUTHORIZE_API,
	    'access_token_uri' =>  GOOGLE_OAUTH_ACCESS_TOKEN_API
    );
    $options = array_merge($options, $extra_options);
    $store = OAuthStore::instance($store_type, $options);
    return $store;
  }
  
  public static function storeSetUp($consumer_key, $consumer_secret, $user_id=1, $store_type="MySQL", $extra_options=array()) {
    //Set up the store for the user id. Only run this once.
    $store = OAuthClient::storeInstance($consumer_key, $consumer_secret, $store_type="MySQL", $extra_options);
  	$ckey = $store->updateServer($options, $user_id);
  }

  public static function getAuthURL($consumer_key, $consumer_secret, $user_id=1, $store="MySQL", $callback=null, $extra_options=array()) {
    //return the authorization URL. Redirect the header to this location.
    OAuthClient::storeInstance($consumer_key, $consumer_secret, $store_type="MySQL", $extra_options);
  
    $getAuthTokenParams = array('scope' => 'http://www.google.com/fusiontables/api/query',
									              'oauth_callback' => $callback);

	  $tokenResultParams = OAuthRequester::requestRequestToken($consumer_key, $user_id, $getAuthTokenParams);

	  return "Location: ".GOOGLE_OAUTH_AUTHORIZE_API.
		     "?oauth_token=".$tokenResultParams['token'].
		     "&scope=".$getAuthTokenParams['scope'].
		     "&domain=".$consumer_key;
  }
  
  public static function authorize($consumer_key, $consumer_secret, $oauth_token, $verifier, $user_id=1, $store="MySQL", $extra_options=array()) {
    //Obtain an access token. This token can be reused until it expires.
		OAuthClient::storeInstance($consumer_key, $consumer_secret, $store_type="MySQL", $extra_options);
		
	  try {
		  OAuthRequester::requestAccessToken($consumer_key, $oauth_token, $user_id, 'POST', array('oauth_token' => $oauth_token, 'oauth_verifier' => $verifier));
	
	  } catch (OAuthException2 $e) {
		  var_dump($e);
		  return;
	  }
  }
}

class FTOAuthClient {

  function __construct($consumer_key, $consumer_secret, $store_type="MySQL", $extra_options=array()) {
    OAuthClient::storeInstance($consumer_key, $consumer_secret, $store_type="MySQL", $extra_options);
  }
  
  function query($query, $user_id=1) {
  
  	if(preg_match("/^SELECT|^SHOW|^DESCRIBE/i", $query)) {
		  $request = new OAuthRequester("http://www.google.com/fusiontables/api/query?sql=".rawurlencode($query), 'GET');
		
	  } else {
		  $request = new OAuthRequester("http://www.google.com/fusiontables/api/query", 'POST', "sql=".rawurlencode($query));
		
	  }
	  $result = $request->doRequest($user_id);
	
	  if ($result['code'] == 200) {
		   return $result['body'];
	
	  } else {
		   return null;
	  }
		
  }

}

?>
