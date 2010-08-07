<?php

require_once('AuthPlugin.php');

# settings:
#$wgRestAuthURL
#$wgRestAuthService
#$wgRestAuthServicePassword

class RestAuthPlugin extends AuthPlugin {
	function getCurlSession( $urlPath ) {
		/**
		 * Set authentication for a curl session
		 */
		global $wgRestAuthURL, 
			$wgRestAuthService, $wgRestAuthServicePassword;
		$url = $wgRestAuthURL . $urlPath;
		$session = curl_init(); 
		curl_setopt($session, CURLOPT_URL, $url);
		curl_setopt($session, CURLOPT_HEADER, 1);
		curl_setopt($session, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($session, CURLOPT_TIMEOUT, 10 );

		curl_setopt($session, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
		curl_setopt($session, CURLOPT_USERPWD, 
			$wgRestAuthService . ':' .$wgRestAuthServicePassword);
		return $session;
	}

	public function userExists ($username) {
		/**
		 * Verify that a user exists.
		 */
		$user = urlencode( strtolower( $username ) );
		$session = $this->getCurlSession( '/users/' . $user . '/');
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
		$session = $this->getCurlSession( '/users/' . $user . '/');
		
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
		$session = $this->getCurlSession( '/users/' . $user . '/');
		
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
		$session = $this->getCurlSession( '/users/' );
		
		# set post data:
		$username= urlencode( strtolower( $user->getName() ) );
		$postData = "username=" . $username . "&password=" . urlencode( $password );
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
