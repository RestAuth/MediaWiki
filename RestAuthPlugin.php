<?php

require_once( 'AuthPlugin.php' );
require_once( '/usr/share/php-restauth/restauth.php' );

# group handling:
$wgHooks['UserAddGroup'][] = 'fnRestAuthUserAddGroup';
$wgHooks['UserRemoveGroup'][] = 'fnRestAuthUserRemoveGroup';

# settings/options
$wgHooks['UserSaveSettings'][] = 'fnRestAuthSaveSettings';
$wgHooks['UserSaveOptions'][] = 'fnRestAuthSaveOptions';

# auto-update local database 
$wgHooks['BeforeInitialize'][] = 'fnRestAuthUpdatePreferences';

/**
 * This function is called upon every pageview and refreshes the local database
 * cache if the last refresh is more than $RestAuthRefresh seconds ago.
 *
 * Please see the documentation for the BeforeInitialize Hook if needed.
 */
function fnRestAuthUpdatePreferences( $title, $article, $output, $user, $request, $this ) {
	if ( $title->getNamespace() === NS_SPECIAL && 
			SpecialPage::resolveAlias( $title->getText() ) === "Preferences" ) {
		// update on Special:Preferences in any case
		global $wgAuth;
		$wgAuth->updateSettings( $conn, $user );
		return true;
	}

	if ( ! $user->isLoggedIn() ) {
		return true; // nothing to do for anonymous users
	}

	global $RestAuthRefresh;
	if ( is_null( $RestAuthRefresh ) ) {
		$RestAuthRefresh = 300;
	}

	// Update local database if the last refresh is more than
	// RestAuthRefresh seconds ago:
	$now = time();
	$timestamp = $user->getIntOption( 'RestAuthRefreshTimestamp', $now );
	if ( $timestamp + $RestAuthRefresh < $now ) {
		global $wgAuth;
		$wgAuth->updateUser( $user );
	}

	return true;
}

/**
 * Helper function to see if an option is a global option or not.
 */
function fnRestAuthGetOptionName( $option ) {
	global $wgRestAuthGlobalOptions;
	if ( array_key_exists( $option, $wgRestAuthGlobalOptions ) &&
			$wgRestAuthGlobalOptions[$option] ) {
		return $option;
	} else {
		return 'mediawiki ' . $option;
	}
}

function fnRestAuthSaveSettings( $user ) {
	global $wgRestAuthIgnoredOptions, $wgRestAuthGlobalOptions;
	$conn = fnRestAuthGetConnection();
	$rest_user = new RestAuthUser( $conn, $user->getName() );

	try {
		$props = $rest_user->get_properties();
	
		// set real name
		$prop = fnRestAuthGetOptionName( 'real name' );
		if ( $user->mRealName && $user->mRealName !== $props[$prop] ) {
			// real name is set

			if ( ! array_key_exists( $prop, $props ) ) {
				// not set in restauth so far
				$rest_user->create_property( $prop, $user->mRealName );
			} elseif ( $user->mRealName !== $props[$prop] ) {
				// set, but have a different value remotely:
				$rest_user->set_property( $prop, $user->mRealName );
			}
			// else: local property identical to remote property
		} elseif ( (! $user->mRealName) && 
				array_key_exists( $prop, $props ) ) {
			// We set an empty value and RestAuth defines a real
			// name. This is equivalent to a deletion request.
			$rest_user->remove_property( $prop );
		}

		// handle email:
		$prop = fnRestAuthGetOptionName( 'email' );
		if ( strpos( $prop, 'mediawiki ' ) === 0 ) {
			$prop_confirmed = 'mediawiki email confirmed';
		} else {
			$prop_confirmed = 'email confirmed';
		}

		if ( $user->mEmail && $user->mEmail !== $props[$prop] ) {
			$dbw = wfGetDB( DB_MASTER );
			$rest_user->set_property( $prop, $user->mEmail );
	
			// value for $confirmed copied from User.php:2526
			// (version 1.16.0)
			$confirmed = $dbw->timestampOrNull( 
				$user->mEmailAuthenticated );

			if ( ! array_key_exists( $prop_confirmed, $props ) 
					&& $confirmed ) {
				// confirmed and not set remotely:
				$rest_user->create_property( $prop_confirmed, '1' );
			} elseif ( array_key_exists( $prop_confirmed, $props ) 
					&& ! $confirmed ) {
				// nut confirmed but confirmed remotely
				$rest_user->remove_property( $prop_confirmed );
			}
		} elseif ( ! $user->mEmail ) {
			if ( array_key_exists( $prop, $props ) ) {
			// We set an empty value and RestAuth defines an email.
			// This is equivalent to a deletion request.
				$rest_user->remove_property( $prop );
			}
			if ( array_key_exists( $prop_confirmed, $props ) ) {
				$rest_user->remove_property( $prop_confirmed );
			}
		}

		return true;
	} catch (RestAuthException $e) {
		throw new MWRestAuthError( $e );
	}
}

/**
 * Save options to the RestAuth database. If a value is set back to its default
 * value, it is deleted from the RestAuth database. It ignores any settings
 * named in the setting $wgRestAuthIgnoredOptions.
 */
function fnRestAuthSaveOptions( $user, $options ) {
	global $wgRestAuthIgnoredOptions;
	$conn = fnRestAuthGetConnection();
	$rest_user = new RestAuthUser( $conn, $user->getName() );
	$update_options = array();
	$create_options = array();
	
	# Get options from RestAuth service:
	try {
		$remote_options = $rest_user->get_properties();
	} catch (RestAuthException $e) {
		throw new MWRestAuthError( $e );
	}

	foreach( $saveOptions as $key => $value ) {
		if ( in_array( $key, $wgRestAuthIgnoredOptions ) ) {
			continue; // filter ignored options
		}
		
		// get name that this option has remotly 
		$prop = fnRestAuthGetOptionName( $key );

		if ( array_key_exists( $prop, $remote_options ) ) {
			if ( $remote_options[$prop] != $value ) {
				try {
					$rest_user->set_property( $prop, $value );
				} catch (RestAuthException $e ) {
					throw new MWRestAuthError( $e );
				}
			} 
		} else {
			// The setting does not yet exist in the
			// RestAuth service. Only save it when the new
			// setting is different from the local default.

			if ( ( is_null( User::getDefaultOption( $key ) ) &&
					!( $value === false || is_null($value) ) ) ||
					 $value != User::getDefaultOption( $key ) ) {
				try {
					$rest_user->create_property( $prop, $value );
				} catch (RestAuthPropertyExists $e ) {
					$rest_user->set_property( $prop, $value );
					throw new MWRestAuthError( $e );
				} catch (RestAuthException $e ) {
					throw new MWRestAuthError( $e );
				}
			}
		}
	}

	// return true so we still save to the database. This way we still have
	// somewhat valid settings here in case the RestAuth service is
	// temporarily unavailable.
	return true;
}

/**
 * Called when a bureaucrat adds the user to a group via Special:UserRights.
 */
function fnRestAuthUserAddGroup( $user, $group ) {
	$conn = fnRestAuthGetConnection();
	$group = RestAuthGroup( $conn, $group );
	try {
		$group->add_user( $user->getName() );
	} catch (RestAuthException $e) {
		throw new MWRestAuthError( $e );
	}
	return true;
}

/**
 * Called when a bureaucrat removes a group from a user via Special:UserRights.
 */
function fnRestAuthUserRemoveGroup( $user, $group ) {
	$conn = fnRestAuthGetConnection();
	$group = RestAuthGroup( $conn, $group );
	try {
		$group->remove_user( $user->getName() );
	} catch (RestAuthException $e) {
		throw new MWRestAuthError( $e );
	}
	return true;
}

/**
 * Helper function to get a connection object to the RestAuth service.
 */
function fnRestAuthGetConnection() {
	global $wgRestAuthHost, $wgRestAuthService, $wgRestAuthServicePassword;
	if ( ! isset( $wgRestAuthHost ) ) $wgRestAuthHost = 'http://localhost';

	return RestAuthConnection::get_connection( $wgRestAuthHost, 
		$wgRestAuthService, $wgRestAuthServicePassword );
}

class RestAuthPlugin extends AuthPlugin {

	public function __construct() {
		$this->conn = fnRestAuthGetConnection();
	}

	/**
	 * Verify that a user exists.
	 */
	public function userExists ($username) {
		try {
			RestAuthUser::get( $this->conn, $username );
			return true;
		} catch (RestAuthResourceNotFound $e) {
			return false;
		} catch (RestAuthException $e) {
			throw new MWRestAuthError( $e );
		}
	}
	
	/** 
	 * Check if a username+password pair is a valid login.
	 */
	public function authenticate ($username, $password) {
		$user = new RestAuthUser( $this->conn, $username );
		try {
			if ( $user->verify_password( $password ) ) {
				return true;
			} else {
				return false;
			}
		} catch (RestAuthException $e) {
			throw new MWRestAuthError( $e );
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

	private static function newTouchedTimestamp() {
                global $wgClockSkewFudge;
                return wfTimestamp( TS_MW, time() + $wgClockSkewFudge );
        }

	public static function updateOptions( &$user ) {
                global $wgAllowPrefChange;

                $extuser = ExternalUser::newFromUser( $user );

		// hack to load options:
                //$user->loadOptions();
		$user->getOption( 'foo', 'bar' );

                $dbw = wfGetDB( DB_MASTER );

                $insert_rows = array();

                $saveOptions = $user->mOptions;

		// hook call removed here

                foreach( $saveOptions as $key => $value ) {
                        # Don't bother storing default values
                        if ( ( is_null( User::getDefaultOption( $key ) ) &&
                                        !( $value === false || is_null($value) ) ) ||
                                        $value != User::getDefaultOption( $key ) ) {
                                $insert_rows[] = array(
                                                'up_user' => $user->getId(),
                                                'up_property' => $key,
                                                'up_value' => $value,
                                        );
                        }  
                        if ( $extuser && isset( $wgAllowPrefChange[$key] ) ) {
                                switch ( $wgAllowPrefChange[$key] ) {
                                        case 'local':
                                        case 'message':
                                                break;
                                        case 'semiglobal':
                                        case 'global':
                                                $extuser->setPref( $key, $value );
                                }
                        }
                }

		$dbw->begin();
                $dbw->delete( 'user_properties', array( 'up_user' => $user->getId() ), __METHOD__ );
                $dbw->insert( 'user_properties', $insert_rows, __METHOD__ );
                $dbw->commit();
	}

	public static function updateSettings( &$conn, &$user ) {
		// initialize local user:
		$user->load();
		if ( wfReadOnly() ) { return; }
		if ( 0 == $user->mId ) { return; }

		// get remote user:
		global $wgRestAuthIgnoredOptions, $wgRestAuthGlobalOptions;
		$rest_user = new RestAuthUser( $conn, $user->getName() );

		// used as a complete list of all options:
		$default_options = User::getDefaultOptions();

		// get all options from the RestAuth service
		try {
			$rest_options = $rest_user->get_properties();
		} catch (RestAuthException $e) {
			// if this is the case, we just don't load any options.
			wfDebug( "Unable to get options from auth-service: " . $e );
			return true;
		}

		// take care of setting all settings and options to the current
		// user object.
		foreach( $rest_options as $key => $value ) {
			if ( strpos( $key, 'mediawiki ' ) === 0 ) {
				// if this is a mediawiki specific setting, remove the
				// prefix:
				$prop_name = substr( $key, 10 );
			} else {
				// This setting is not specific to MediaWiki. Only use
				// the setting if we find it in $wgRestAuthGlobalOptions.
				if ( ! ( array_key_exists( $key, $wgRestAuthGlobalOptions )
						&& $wgRestAuthGlobalOptions[$key] ) ) {
					continue;
				}

				// This is a global option where we also have an option
				// specific to MediaWiki - which we use instead
				if ( array_key_exists( 'mediawiki ' . $key, $rest_options ) ) {
					continue;
				}
				$prop_name = $key;
			}
		
			if ( in_array( $prop_name, $wgRestAuthIgnoredOptions ) ) {
				continue; // filter ignored options
			}

			if ( $prop_name == 'real name' ) {
				$user->mRealName = $value;
			} elseif ( $prop_name == 'email' ) {
				$user->mEmail = $value;
			} elseif ( $prop_name == 'email confirmed' ) {
				$user->mEmailConfirmed = $value;
			} elseif ( array_key_exists( $prop_name, $default_options ) ) {
				// finally use the property from RestAuth, if the
				// property exists as a default option:
				$user->mOptions[$prop_name] = $value;
				$user->mOptionsOverrides[$prop_name] = $value;
			}
		}

		// update RestAuthRefreshTimestamp:
		$user->mOptions['RestAuthRefreshTimestamp'] = time();

		// begin saving the user to the local database:
		$user->mTouched = self::newTouchedTimestamp();

		$dbw = wfGetDB( DB_MASTER );
                $dbw->update( 'user',
                        array( /* SET */
                                'user_name' => $user->mName,
                                'user_password' => $user->mPassword,
                                'user_newpassword' => $user->mNewpassword,
                                'user_newpass_time' => $dbw->timestampOrNull( $user->mNewpassTime ),
                                'user_real_name' => $user->mRealName,
                                'user_email' => $user->mEmail,
                                'user_email_authenticated' => $dbw->timestampOrNull( $user->mEmailAuthenticated ),
                                'user_options' => '',
                                'user_touched' => $dbw->timestamp( $user->mTouched ),
                                'user_token' => $user->mToken,
                                'user_email_token' => $user->mEmailToken,
                                'user_email_token_expires' => $dbw->timestampOrNull( $user->mEmailTokenExpires ),
                        ), array( /* WHERE */
                                'user_id' => $user->mId
                        ), __METHOD__
                );

                RestAuthPlugin::updateOptions( $user );

                $user->invalidateCache();
                $user->getUserPage()->invalidateCache();
	}

	/**
 	  * Synchronize the local group database with the remote database.
	  */
	public static function updateGroups( &$conn, &$user ) {
		$user->load();
		$user->loadGroups();
		$rest_groups = RestAuthGroup::get_all( $conn, $user->getName() );
		$remote_groups = array();
		foreach ( $rest_groups as $rest_group ) {
			$remote_groups[] = $rest_group->name;
		}

		# get database slave:
		$dbw = wfGetDB( DB_MASTER );

		# remove groups no longer found in the remote database:
		$rem_groups = array_diff( $user->mGroups, $remote_groups );
		foreach ( $rem_groups as $group ) {
			$dbw->delete( 'user_groups',
				array(
					'ug_user'  => $user->getID(),
					'ug_group' => $group,
				),
				'RestAuthPlugin::updateGroups' );
		}

		# add new groups found in the remote database:
		$add_groups = array_diff( $remote_groups, $user->mGroups );
		foreach ( $add_groups as $group ) {
			if( $user->getId() ) {
				$dbw->insert( 'user_groups',
					array(
						'ug_user'  => $user->getID(),
						'ug_group' => $group,
					),
					'RestAuthPlugin::updateGroups',
					array( 'IGNORE' ) );
			}
		}

		$user->loadGroups();
		$user->mGroups = $remote_groups;
		$user->mRights = User::getGroupPermissions( $user->getEffectiveGroups( true ) );
		$user->invalidateCache();
	}

	/**
	 * Called whenever a user logs in. It updates local groups to mach those
	 * from the remote database.
	 */
	function updateUser (&$user) {
		# When a user logs in, optionally fill in preferences and such.	
		RestAuthPlugin::updateGroups( $this->conn, $user );
		RestAuthPlugin::updateSettings( $this->conn, $user );
	}

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
		try {
			$user = new RestAuthUser( $this->conn, $user->getName() );
			$user->set_password( $password );
			return true;
		} catch (RestAuthException $e) {
			throw new MWRestAuthError( $e );
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
		try {
			RestAuthUser::create( $this->conn, $user->getName(), $password );
			return true;
// TODO: email, realname?
		} catch (RestAuthException $e) {
			throw new MWRestAuthError( $e );
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

	function initUser (&$user, $autocreate=false) {
		# When creating a user account, optionally fill in preferences
		# and such.
		RestAuthPlugin::updateGroups( $this->conn, $user );
		RestAuthPlugin::updateSettings( $this->conn, $user );
	}

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
