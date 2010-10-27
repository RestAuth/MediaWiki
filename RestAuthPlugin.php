<?php

# settings:
#$wgRestAuthURL
#$wgRestAuthService
#$wgRestAuthServicePassword

require_once( 'AuthPlugin.php' );
require_once( '/usr/share/php-restauth/restauth.php' );

$wgHooks['UserEffectiveGroups'][] = 'fnRestAuthUserEffectiveGroups';
$wgHooks['UserAddGroup'][] = 'fnRestAuthUserAddGroup';
$wgHooks['UserRemoveGroup'][] = 'fnRestAuthUserRemoveGroup';
$wgHooks['UserGetAllGroups'][] = 'fnRestAuthGetAllGroups';

$wgHooks['UserSetEmail'][] = 'fnRestAuthSetEmail';
$wgHooks['UserGetEmail'][] = 'fnRestAuthGetEmail';

function fnRestAuthSetEmail( $user, $mail ) {
	//TODO: Set email
}
function fnRestAuthGetEmail( $user, $mail ) {
	//TODO: Get email
}

function fnRestAuthUserEffectiveGroups( $user, $groups ) {
	#TODO: Error hanlding.
	$conn = restauth_get_connection();
	$rest_groups = RestAuthGetAllGroups( $conn, $user->getName() );
	//TODO: whatever this returns?

	foreach ($rest_groups as $group) {
		if ( ! in_array( $group, $groups ) ) {
			$groups[] = $group;
		}
	}
	return true;
}

function fnRestAuthUserAddGroup( $user, $group, $saveLocal ) {
	#TODO: Error hanlding.
	$conn = restauth_get_connection();
	$group = RestAuthGroup( $conn, $group );
	$group->remove_user( $user->getName() );
	return true;
}

function fnRestAuthUserRemoveGroup( $user, $group, $saveLocal ) {
	#TODO: Error handling
	$conn = restauth_get_connection();
	$group = RestAuthGroup( $conn, $group );
	$group->remove_user( $user->getName() );
	return true;
}

function fnRestAuthGetAllGroups( $user, $externalGroups ) {
	#TODO: Error hanlding.
	$conn = restauth_get_connection();
	$rest_groups = RestAuthGetAllGroups( $conn );
	foreach( $rest_groups as $group ) {
		$externalGroups[] = $group;
	}
	return true;
}

/**
 * Helper function to get a connection object to the RestAuth service.
 */
function restauth_get_connection() {
	global $wgRestAuthHost, $wgRestAuthPort, $wgRestAuthService,
		$wgRestAuthServicePassword;

	if ( ! $wgRestAuthHost )
		$wgRestAuthHost = 'localhost';
	if ( ! $wgRestAuthPort )
		$wgRestAuthPort = 80;
	
	return new RestAuthConnection( $wgRestAuthHost, $wgRestAuthPort,
		$wgRestAuthService, $wgRestAuthServicePassword );
}

class RestAuthPlugin extends AuthPlugin {

	public function __construct() {
		$this->conn = restauth_get_connection();
	}

	/**
	 * Verify that a user exists.
	 */
	public function userExists ($username) {
		try {
			RestAuthGetUser( $this->conn, $username );
			return true;
		} catch ( RestAuthUserNotFound $e ) {
			return false;
		}
	}
	
	/** 
	 * Check if a username+password pair is a valid login.
	 */
	public function authenticate ($username, $password) {
		$user = new RestAuthUser( $this->conn, $username );
		try {
			if ( $user->verify_password( $password ) ) {
				print( 'verified' );
				return true;
			} else {
				print( 'not verified' );
				return false;
			}
		} catch ( RestAuthUnauthorized $e ) {
			wfDebug( 'Could not authenticate against the RestAuth service, check $wgRestAuthService and $wgRestAuthServicePassword and if that service exists in the RestAuth webservice.' );
			throw new MWException( 'Could not contact the authentication server, please try again later.' );
		} catch ( RestAuthInternalServerError $e ) {
			throw new MWException( 'The authentication service is temporarily unavailable. Please try again later.' );
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
		$user = new RestAuthUser( $this->conn, $user->getName() );
		$user->set_password( $password );
		return true;
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
		try {
			RestAuthCreateUser( $this->conn, $user->getName(), $password );
			return true;
		} catch ( RestAuthUserExists $e ) {
			throw new ErrorPageError( "error-user-exists-header", 'error-user-exists-body' );
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
