<?php

# settings:
#$wgRestAuthURL
#$wgRestAuthService
#$wgRestAuthServicePassword

require_once('AuthPlugin.php');
$wgHooks['UserEffectiveGroups'][] = 'fnRestAuthUserEffectiveGroups';
$wgHooks['UserAddGroup'][] = 'fnRestAuthUserAddGroup';
$wgHooks['UserRemoveGroup'][] = 'fnRestAuthUserRemoveGroup';
$wgHooks['UserGetAllGroups'][] = 'fnRestAuthGetAllGroups';

function fnRestAuthUserEffectiveGroups( $user, $groups ) {
	$username = sanitizeUsername( $user->getName() );
	$session = getCurlSession( '/groups/?user=' . $username);
	$response = curl_exec($session);
	$status = curl_getinfo( $session, CURLINFO_HTTP_CODE );
	$header_size = curl_getinfo( $session, CURLINFO_HEADER_SIZE );
	$body = substr( $response, $header_size );
	curl_close( $session );

	switch ( $status ) {
		case 200:
			$rest_groups = json_decode( $body );
			foreach ($rest_groups as $value) {
				if ( ! in_array( $value, $groups ) ) {
					$groups[] = $value;
				}
			}
			break;
		# TODO: Error handling?
	};

	return true;
}

function fnRestAuthUserAddGroup( $user, $group, $saveLocal ) {
	$username = sanitizeUsername( $user->getName() );
	$session = getCurlSession( '/groups/' . $group . '/' );
	$postData = 'user=' . $username . '&autocreate=true';
	curl_setopt($session, CURLOPT_POST, true); 
	curl_setopt($session, CURLOPT_POSTFIELDS, $postData);
	
	$response = curl_exec($session);
	$status = curl_getinfo( $session, CURLINFO_HTTP_CODE );
	#TODO: Error hanlding.
	return true;
}

function fnRestAuthUserRemoveGroup( $user, $group, $saveLocal ) {
	$username = sanitizeUsername( $user->getName() );
	$session = getCurlSession( '/groups/' . $group . '/' . $username . '/' );
	curl_setopt($session, CURLOPT_CUSTOMREQUEST, 'DELETE'); 

	$response = curl_exec( $session );
	$status = curl_getinfo( $session, CURLINFO_HTTP_CODE );
	#TODO: Error handling
	return true;
}

function getCurlSession( $urlPath ) {
	/**
	 * Set authentication for a curl session
	 */
	global $wgRestAuthURL, $wgRestAuthService, $wgRestAuthServicePassword;
	$url = $wgRestAuthURL . $urlPath;
	$session = curl_init(); 
	curl_setopt($session, CURLOPT_URL, $url);
	curl_setopt($session, CURLOPT_HEADER, 1);
	curl_setopt($session, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($session, CURLOPT_TIMEOUT, 10 );
	curl_setopt($session, CURLOPT_HTTPHEADER, array(
		'Content-Type: application/json',
		'Accept: application/json',
	));

	curl_setopt($session, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
	curl_setopt($session, CURLOPT_USERPWD, 
		$wgRestAuthService . ':' .$wgRestAuthServicePassword);
	return $session;
}

function fnRestAuthGetAllGroups( $user, $externalGroups ) {
	print( "fnRestAuthGetAllGroups\n" );
#	die();
	$session = getCurlSession( '/groups/' );
	$response = curl_exec($session);
	$header_size = curl_getinfo( $session, CURLINFO_HEADER_SIZE );
	$body = substr( $response, $header_size );
	$groups = json_decode( $body );
	foreach( $groups as $group ) {
		$externalGroups[] = $group;
	}
	return true;
}

function sanitizeUsername( $username ) {
	return urlencode( strtolower( $username ) );
}

class RestAuthPlugin extends AuthPlugin {

	public function userExists ($username) {
		/**
		 * Verify that a user exists.
		 */
		$user = sanitizeUsername( $username );
		$session = getCurlSession( '/users/' . $user . '/');
		curl_exec($session);
		$status = curl_getinfo( $session, CURLINFO_HTTP_CODE );
		switch ( $status ) {
			case 200: 
				return true;
				break;
			default:
				return false;
		}
	}
	
	public function authenticate ($username, $password) {
		/** 
		 * Check if a username+password pair is a valid login.
		 */
		$user = urlencode( strtolower( $username ) );
		$session = getCurlSession( '/users/' . $user . '/');
		
		# set post data:
		$postData = "password=" . urlencode( $password );
		curl_setopt($session, CURLOPT_POST, 1); 
		curl_setopt($session, CURLOPT_POSTFIELDS, $postData);
		
		$data = curl_exec($session);
		$status = curl_getinfo( $session, CURLINFO_HTTP_CODE );
		curl_close($session); 
		switch ( $status ) {
			case 200: 
				return true;
				break;
			default:
				return false;
		}
	}

/*	function modifyUITemplate (&$template, &$type) {
		# Modify options in the login template.
	}
*/
/*	function setDomain ($domain) {
		# Set the domain this plugin is supposed to use when
		# authenticating.
	}
*/
	public function validDomain ($domain) {
		/**
		 * Always returns true (we do not use any domains)
		 */
		return true;
	}

/*	function updateUser (&$user) {
		# When a user logs in, optionally fill in preferences and such.
	}
*/
	public function autoCreate () {
		# Return true if the wiki should create a new local account
		# automatically when asked to login a user who doesn't exist
		# locally but does in the external auth database.
		return true;
	}

/*	function allowPropChange ($prop= '') {
		# Allow a property change? Properties are the same as
		# preferences and use the same keys.
	}
*/
	public function allowPasswordChange () {
		return true;
	}
	
	public function setPassword ($user, $password) {
		# Set the given password in the authentication database.
		$user = urlencode( strtolower( $user->getName() ) );
		$session = getCurlSession( '/users/' . $user . '/');
		
		# set post data:
		$postData = "password=" . urlencode( $password );
		curl_setopt($session, CURLOPT_CUSTOMREQUEST, 'PUT'); 
		curl_setopt($session, CURLOPT_HTTPHEADER, array(
			'Content-Length: ' . strlen($postData) ) ); 
		curl_setopt($session, CURLOPT_POSTFIELDS, $postData);
		
		$data = curl_exec($session);
		$status = curl_getinfo( $session, CURLINFO_HTTP_CODE );
		curl_close($session); 

		switch ( $status ) {
			case 200:
				return true;
				break;
			default:
				return false;
		}
	}
	
/*	function updateExternalDB ($user) {
		# Update user information in the external authentication
		# database.
		print( 'updateExternalDB' );
	}
*/
	public function canCreateAccounts () {
		/**
		 * Always returns true
		 */
		return true;
	}

	public function addUser ($user, $password, $email= '', $realname= '') {
		# Add a user to the external authentication database.
		$session = getCurlSession( '/users/' );
		
		# set post data:
		$username= urlencode( strtolower( $user->getName() ) );
		$postData = "user=" . $username . "&password=" . urlencode( $password );
		curl_setopt($session, CURLOPT_POST, true); 
		curl_setopt($session, CURLOPT_POSTFIELDS, $postData);
		
		$data = curl_exec($session);
		$status = curl_getinfo( $session, CURLINFO_HTTP_CODE );
		curl_close($session); 

		switch ( $status ) {
			case 201:
				return true;
				break;
			default:
				return false;
		}
	}

	public function strict () {
		/**
		 * Always returns true. This stops MediaWiki from checking 
		 * against the local database's password fields in case the
		 * RestAuth authentication fails.
		 */
		return true;
	}

	public function strictUserAuth ($username) {
		# Check if a user should authenticate locally if the global
		# authentication fails.
		return true;
	}

/*	function initUser (&$user, $autocreate=false) {
		# When creating a user account, optionally fill in preferences
		# and such.
	}
*/
/*	function getCanonicalName ($username) {
		# If you want to munge the case of an account name before the
		# final check, now is your chance.
	}
*/
/*	function getUserInstance (User &$user) {
		# Get an instance of a User object.
	}
*/
}
