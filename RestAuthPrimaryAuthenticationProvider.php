<?php
namespace MediaWiki\Auth;

use User;

require_once('RestAuth/restauth.php');
require_once('RestAuthError.php');

/**
 * A primary authentication provider that authenticates the user against a RestAuth instance.
 *
 * @ingroup Auth
 * @since 1.27
 */
class RestAuthPrimaryAuthenticationProvider extends AbstractPrimaryAuthenticationProvider {
	/* RestAuth variables */
	var $wgRestAuthHost = 'localhost';

	/**
	* List of ignored =>preferences.
	*
	* This may either be an =>option or a =>setting, exactly as defined in
	* *MediaWiki*.
	*/
	var $wgRestAuthIgnoredPreferences = array(
		"RestAuthRefreshTimestamp",
		"watchlisttoken",
	);

	/**
	* wgRestAuthGlobalProperties defines what =>properties are global.
	* Non-global properties will be saved to RestAuth with the prefix 'mediawiki '.
	*
	* NOTE: The keys defined here are property names *in RestAuth* and not of
	* MediaWiki options. The key difference is that 'full name' and
	* 'email confirmed' are standard RestAuth options and are mapped accordingly.
	*
	* If any =>options are added here, the name in RestAuth and MediaWiki should be
	* identical, otherwise the code has to be modified.
	*/
	var $wgRestAuthGlobalProperties = array(
		'language' => true,
		'full name' => true,
		'email' => true,
		'email confirmed' => true,
	);
	var $wgRestAuthRefresh = 300;

	public function __construct() {
		global $wgRestAuthHost;
		if (isset($wgRestAuthHost)) {
			$this->wgRestAuthHost = $wgRestAuthHost;
		}

		$this->conn = fnRestAuthGetConnection();

		$this->preferenceMapping = array(
			// NOTE: 'full name' is a predefined property name.
			'mRealName' => $this->raPropertyName('full name'),
			'email' => $this->raPropertyName('email'),
			// email_confirmed is handled seperately - see below
		);
	}

    /**
     * Verify that a user exists.
     */
	public function testUserExists( $username, $flags = User::READ_NORMAL ) {
        try {
            RestAuthUser::get($this->conn, $username);
            return true;
        } catch (RestAuthResourceNotFound $e) {
            return false;
        } catch (RestAuthException $e) {
            throw new MWRestAuthError($e);
        }
	}

    /**
     * Check if a username+password pair is a valid login.
     */
	public function beginPrimaryAuthentication( array $reqs ) {
		$req = AuthenticationRequest::getRequestByClass( $reqs, PasswordAuthenticationRequest::class );
		if ( !$req ) {
			return AuthenticationResponse::newAbstain();
		}

		if ( $req->username === null || $req->password === null ) {
			return AuthenticationResponse::newAbstain();
		}

		$username = User::getCanonicalName( $req->username, 'usable' );
		if ( $username === false ) {
			return AuthenticationResponse::newAbstain();
		}

        $user = new RestAuthUser($this->conn, $req->username);
        try {
            if ($user->verifyPassword($req->password)) {
                return AuthenticationResponse::newPass();
            } else {
                return AuthenticationResponse::newFail();
            }
        } catch (RestAuthException $e) {
            throw new MWRestAuthError($e);
        }
	}

	/**
	 * Allow password change
	 */
	public function providerAllowsAuthenticationDataChange( AuthenticationRequest $req, $checkData = true ) {
		$auth_req = AuthenticationRequest::getRequestByClass( array($req), PasswordAuthenticationRequest::class );
		if ( !$auth_req ) {
			return \StatusValue::newError("this is no password authentication request");
		}
	}

	/**
	 * Actually do the password change
	 */
	public function providerChangeAuthenticationData( AuthenticationRequest $req ) {
		$auth_req = AuthenticationRequest::getRequestByClass( array($req), PasswordAuthenticationRequest::class );
		if ( !$auth_req ) {
			return \StatusValue::newError("this is no password authentication request");
		}
        try {
            $user = new RestAuthUser($this->conn, $req->username);
            $user->setPassword($req->password);
            return true;
        } catch (RestAuthException $e) {
            throw new MWRestAuthError($e);
        }
	}

	/**
	 * If accounts can be created
	 */
	public function accountCreationType() {
		return self::TYPE_CREATE;
	}

	/**
	 * first step of account creation: validate the username
	 */
	public function testUserForCreation( $user, $autocreate, array $options = [] ) {
		// TODO: validate the username instead of just rejecting uppercase logins
		global $wgContLang;
		if ($wgContLang->lc($user->getName()) != $user->getName()) {
			return \StatusValue::newFatal("Please login with username in lowercase");
		}
		return \StatusValue::newGood();
	}

	/**
	 * second step of account creation: prevalidate the user
	 */
	public function testForAccountCreation( $user, $creator, array $reqs ) {
		$req = AuthenticationRequest::getRequestByClass( $reqs, PasswordAuthenticationRequest::class );
		if ( !$req ) {
			return \StatusValue::newError("no Password Authentication Request found");
		}
		return \StatusValue::newGood();
	}

	/**
	 * third step of account creation: create the user
	 */
	public function beginPrimaryAccountCreation( $user, $creator, array $reqs ) {
		wfDebug("- START: " . __FUNCTION__ . "\n");

		// find the password auth request
		$auth_req = AuthenticationRequest::getRequestByClass( $reqs, PasswordAuthenticationRequest::class );
		if ( !$auth_req ) {
			return \StatusValue::newFatal("no Password Authentication Request found");
		}

        // create an array of properties, if anything is present
        $properties = array();
        if ($email) {
            $properties['email'] = $email;
        }
        if ($realname) {
            $properties['full name'] = $realname;
        }

        try {
            $name = $user->getName();
            if (empty($properties)) {
                RestAuthUser::create($this->conn, $name, $password);
            } else {
                RestAuthUser::create(
                    $this->conn, $name, $password, $properties);
            }
            wfDebug("-   END: " . __FUNCTION__ . "\n");
            return \StatusValue::newGood();
        } catch (RestAuthException $e) {
            throw new MWRestAuthError($e);
        }
	}

	/**
	 * fourth step of account creation: user has been added to the db
	 */
	public function finishAccountCreation( $user, $creator, AuthenticationResponse $response ) {
		// call sync hook
		$this->onLocalUserCreated($user, $autocreate = true);
		return \StatusValue::newGood();
	}

	// DEFAULT FUNCTIONS / Maybe linking provider: TODO CHECK
	/**
	 * @param null|\User $user
	 * @param AuthenticationResponse $response
	 */
	public function postAuthentication( $user, AuthenticationResponse $response ) {
	}

	public function testUserCanAuthenticate( $username ) {
		// Assume it can authenticate if it exists
		return $this->testUserExists( $username );
	}

	public function providerNormalizeUsername( $username ) {
		$name = User::getCanonicalName( $username );
		return $name === false ? null : $name;
	}

	public function providerRevokeAccessForUser( $username ) {
		$reqs = $this->getAuthenticationRequests(
			AuthManager::ACTION_REMOVE, [ 'username' => $username ]
		);
		foreach ( $reqs as $req ) {
			$req->username = $username;
			$req->action = AuthManager::ACTION_REMOVE;
			$this->providerChangeAuthenticationData( $req );
		}
	}

	public function providerAllowsPropertyChange( $property ) {
		return true;
	}

	public function continuePrimaryAccountCreation( $user, $creator, array $reqs ) {
		throw new \BadMethodCallException( __METHOD__ . ' is not implemented.' );
	}

	public function postAccountCreation( $user, $creator, AuthenticationResponse $response ) {
	}

	public function autoCreatedAccount( $user, $source ) {
	}

	public function beginPrimaryAccountLink( $user, array $reqs ) {
		if ( $this->accountCreationType() === self::TYPE_LINK ) {
			throw new \BadMethodCallException( __METHOD__ . ' is not implemented.' );
		} else {
			throw new \BadMethodCallException(
				__METHOD__ . ' should not be called on a non-link provider.'
			);
		}
	}

	public function continuePrimaryAccountLink( $user, array $reqs ) {
		throw new \BadMethodCallException( __METHOD__ . ' is not implemented.' );
	}

	public function postAccountLink( $user, AuthenticationResponse $response ) {
	}

	// custom functions

	public function getAuthenticationRequests( $action, array $options ) {
		switch ( $action ) {
			case AuthManager::ACTION_LOGIN:
				return [ new PasswordAuthenticationRequest() ];
			default:
				return [];
		}
	}

	/*
	 * *****************************
	 * Helper functions for RestAuth
	 * *****************************
	 */

	/**
	* Function to determine if a users groups/properties need to be updated.
	*/
	function fnRestAuthUserNeedsRefresh($user) {
		global $wgRestAuthRefresh;

		$now = time();
		$timestamp = $user->getIntOption('RestAuthRefreshTimestamp', $now);
		if ($timestamp + $wgRestAuthRefresh < $now) {
			return true;
		} else {
			return false;
		}
	}

	/**
	* This function is called upon every pageview and refreshes the local database
	* cache if the last refresh is more than $RestAuthRefresh seconds ago or we are on
	* Special:Preferences.
	*
	* Please see the documentation for the BeforeInitialize Hook if needed.
	*/
	function fnRestAuthRefreshCurrentUser($title, $article, $output, $user, $request, $mediaWiki) {
		if (!$user->isLoggedIn()) {
			return true;
		}

		$update = false;

		if ($title->isSpecial('Preferences') && $request->getMethod() === 'GET') {
			$update = true; // update when viewing Special:Preferences
		} else {

			// Update local database if the last refresh is more than
			// $wgRestAuthRefresh seconds ago:
			$update = fnRestAuthUserNeedsRefresh($user);
		}

		if ($update) {
			global $wgAuth;
			$wgAuth->updateUser($user);
		}

		return true;
	}

	/**
	* Called when a bureaucrat adds the user to a group via Special:UserRights.
	*/
	function fnRestAuthUserAddGroup($user, &$group) {
		$conn = fnRestAuthGetConnection();
		$ra_group = new RestAuthGroup($conn, $group);
		try {
			$ra_group->addUser($user->getName());
		} catch (RestAuthResourceNotFound $e) {
			$ra_group = RestAuthGroup::create($conn, $group);
			$ra_group->addUser($user->getName());
		} catch (RestAuthException $e) {
			throw new MWRestAuthError($e);
		}
		return true;
	}

	/**
	* Called when a bureaucrat removes a group from a user via Special:UserRights.
	*/
	function fnRestAuthUserRemoveGroup($user, &$group) {
		$conn = fnRestAuthGetConnection();
		$ra_group = new RestAuthGroup($conn, $group);
		try {
			$ra_group->removeUser($user->getName());
	//TODO: catch 404 if we're out of sync with the RestAuth server
		} catch (RestAuthException $e) {
			throw new MWRestAuthError($e);
		}
		return true;
	}

	/**
	* Helper function to get a connection object to the RestAuth service.
	*/
	function fnRestAuthGetConnection() {
		global $wgRestAuthHost, $wgRestAuthService, $wgRestAuthServicePassword;
		if (! isset($wgRestAuthHost)) $wgRestAuthHost = 'http://localhost';

		return RestAuthConnection::getConnection($wgRestAuthHost,
			$wgRestAuthService, $wgRestAuthServicePassword);
	}

	public function continuePrimaryAuthentication( array $reqs ) {
		throw new \BadMethodCallException( __METHOD__ . ' is not implemented.' );
	}

    private function newTouchedTimestamp() {
        global $wgClockSkewFudge;
        return wfTimestamp(TS_MW, time() + $wgClockSkewFudge);
    }

    /**
     * Called whenever a user logs in, =>refreshes =>preferences and groups.
     *
     * NOTE: This function does a =>refresh, not an =>update, but its name
     *       is defined by the AuthPlugin interface.
     *
     * Also called by fnRestAuthRefreshCurrentUser (which registers the
     * BeforeInitialize-Hook), if the user views Special:Preferences or
     * $wgRestAuthRefresh seconds have passed since the last =>refresh.
     */
    public function fnRestAuthUpdateUser ($user) {
        wfDebug("- START: " . __FUNCTION__ . "($user)\n");
        # When a user logs in, optionally fill in preferences and such.
        $this->refreshGroups($user);
        $this->refreshPreferences($user);

        # reload everything
        $user->invalidateCache();
        wfDebug("-   END: " . __FUNCTION__ . "\n");
	}

	/**
	 * Replicate group changes to RestAuth
	 */
	public function fnRestAuthUserGroupsChanged($user, $added, $removed, $performer, $reason, $oldUGMs, $newUGMs) {
		// TODO sync groups
	}

    /**
     * =>Update the external user database with =>preferences.
     *
     * This is called when the user hits 'submit' on Special:Preferences.
	 */
	public function fnRestAuthUserSaveSettings($user) {
        wfDebug("- START: " . __FUNCTION__ . "($user)\n");
        global $wgRestAuthIgnoredPreferences;

        $raUser = new RestAuthUser($this->conn, $user->getName());
        $raProperties = $raUser->getProperties();

        // Properties are collected here and set in one single RestAuth call:
        $raSetProperties = array();
        $raDelProperties = array();

        // Handle =>settings.
        $this->updateExternalDBSettings(
            $raProperties, $raSetProperties, $raDelproperties);

        // Handle =>options.
        foreach($user->getOptions() as $key => $value) {
            if (in_array($key, $wgRestAuthIgnoredPreferences)) {
                continue; // filter ignored options
            }
            $this->_handleUpdateOption($raProperties, $key, $value,
                $raSetProperties, $raDelProperties);

        }

        try {
            // finally set all properties in one go:
            if (count($raSetProperties) > 0) {
                foreach ($raSetProperties as $key => $value) {
                    wfDebug("----- Set '$key --> $value' (" . gettype($value) . ")\n");
                }
                $raUser->setProperties($raSetProperties);
            }

            // .. and delete any properties set back to the default.
            foreach($raDelProperties as $raProp) {
                wfDebug("----- Del '$raProp'\n");
                $raUser->removeProperty($raProp);
            }

            wfDebug("-   END: " . __FUNCTION__ . "\n");
            return true;
        } catch (RestAuthException $e) {
            wfDebug("- EXCEPTION: " . __FUNCTION__ . " - $e\n");
            throw new MWRestAuthError($e);
        }
	}

    /**
     * Update =>settings (NOT =>options!) to the RestAuth database.
     */
    private function updateExternalDBSettings ($raProperties,
        &$raSetProperties, &$raDelProperties)
    {
		global $wgRestAuthIgnoredPreferences;

        wfDebug("- START: " . __FUNCTION__ . "\n");
        foreach ($this->preferenceMapping as $prop => $raProp) {
            if (in_array($prop, $wgRestAuthIgnoredPreferences)) {
                continue; // filter ignored options
            }

            $this->_handleUpdateSetting($raProperties, $raProp, $user->$prop,
                $raSetProperties);
        }

        // email confirmed is handled seperately, because locally its a boolean
        // value and we need to set '0' or '1' remotely (RestAuth properties
        // are always strings).

        // 'email confirmed' is prefixed if 'email' is prefixed.
        if (strpos($this->preferenceMapping['email'], 'mediawiki ') === 0) {
            $raProp = 'mediawiki email confirmed';
        } else {
            $raProp = 'email confirmed';
        }

        // boolean condition copied from includes/User.php:2825 (version 1.19.2)
        $dbw = wfGetDB(DB_MASTER);
        if ($dbw->timestampOrNull($user->mEmailAuthenticated)) {
            $value = '1';
        } else {
            $value = '0';
        }
        $this->_handleUpdateSetting($raProperties, $raProp, $value,
            $raSetProperties);

        wfDebug("-   END: " . __FUNCTION__ . "\n");
    }

    private function _handleUpdateSetting($raProperties, $raProp, $value,
        &$raSetProperties)
    {
//TODO: Normalize value
        if (array_key_exists($raProp, $raProperties)) {
            // setting already in RestAuth
            if ($raProperties[$raProp] != $value) {
                $raSetProperties[$raProp] = $value;
            }
        } else {
            // setting not (yet) in RestAuth
            $raSetProperties[$raProp] = $value;
        }
    }

    private function _handleUpdateOption($raProperties, $option, $value,
            &$raSetProperties, &$raDelProperties)
    {
        $default = User::getDefaultOption($option);
        $raProp = $this->raPropertyName($option);

        // normalize default-value:
        if (is_int($default) || is_double($default)) {
            $default = (string)$default;
        } elseif (is_bool($default)) {
            if ($default === true) {
                $default = '1';
            } else {
                $default = '0';
            }
        } elseif (is_null($default)) {
            // some default values translate differently, depending on what
            // the form sends:
            // * with checkboxes $value === true|false, never null

            if (is_bool($value)) {
                $default = '0';
            } else {
                $default = '';
            }
        }

        // normalize the new value:
        if (is_int($value) || is_double($value)) {
            $value = (string)$value;
        } elseif (is_bool($value)) {
            if ($value === true) {
                $value = '1';
            } else {
                $value = '0';
            }
        }

        if (array_key_exists($raProp, $raProperties)) {
            // setting already in RestAuth

            if ($default === $value) {
                // Set back to default --> remove from RestAuth
                $raDelProperties[] = $raProp;
            } elseif ($raProperties[$raProp] != $value) {
                // RestAuth value different from local --> save to RestAuth
                $raSetProperties[$raProp] = $value;
            }
        } else {
            // setting not (yet) in RestAuth

            if ($default != $value) {
                // new value is not just default --> save to RestAuth
                $raSetProperties[$raProp] = $value;
            }
        }
	}

    /**
     * Initialize a new user. =>Refreshes groups and =>Preferences.
     *
     * This is called when a new user was created ($autocreate=false) or when a
     * user logs in and doesn't yet exist locally ($autocreate=true).
     *
     * We only =>refresh anything if the user was autocreated, if this is a
     * totally new user (to RestAuth AND MediaWiki), there shouldn't be any
     * data in RestAuth.
     */
    public function fnRestAuthLocalUserCreated($user, $autocreate = false) {
        if ($autocreate) {
            // true upon login and user doesn't exist locally
            $this->refreshGroups($user);
            $this->refreshPreferences($user);
        }
    }

    /**
     * =>Refresh =>preferences (=>settings AND =>options!) from RestAuth.
     */
    public function refreshPreferences(&$user) {
        // initialize local user:
        $user->load();
        if (wfReadOnly()) { return; }
        if (0 == $user->mId) { return; }
        wfDebug("- START: " . __FUNCTION__ . "\n");

        // get remote user:
        global $wgRestAuthIgnoredPreferences, $wgRestAuthGlobalProperties;
        $ra_user = new RestAuthUser($this->conn, $user->getName());

        // used as a complete list of all options:
        $default_options = User::getDefaultOptions();

        // get all options from the RestAuth service
        try {
            $raProps = $ra_user->getProperties();
        } catch (RestAuthException $e) {
            // if this is the case, we just don't load any options.
            wfDebug("Unable to get options from auth-service: " . $e . "\n");
            return;
        }

        // take care of setting all settings and options to the current
        // user object.
        foreach($raProps as $raProp => $value) {
            if (strpos($raProp, 'mediawiki ') === 0) {
                // if this is a mediawiki specific =>property, remove the
                // prefix:
                $pref = substr($raProp, 10);
            } else {
                // This =>property is not specific to MediaWiki. Only use
                // the setting if we find it in $wgRestAuthGlobalProperties.
                if (is_null($wgRestAuthGlobalProperties) ||
                    !(array_key_exists($raProp, $wgRestAuthGlobalProperties)
                      && $wgRestAuthGlobalProperties[$raProp]))
                {
                    continue;
                }

                // This is a global =>property where we also have a =>property
                // specific to MediaWiki - which we use instead
                if (array_key_exists('mediawiki ' . $raProp, $raProps)) {
                    continue;
                }
                $pref = $raProp;
            }

            if (!is_null($wgRestAuthIgnoredPreferences) && in_array($pref, $wgRestAuthIgnoredPreferences)) {
                continue; // filter ignored options
            }

            if ($pref == 'full name') {
                $user->mRealName = $value;
            } elseif ($pref == 'email') {
                $user->mEmail = $value;
            } elseif ($pref == 'email confirmed') {
                if ($value === '1') {
                    $user->mEmailConfirmed = true;
                } else {
                    $user->mEmailConfirmed = false;
                }
            } elseif (array_key_exists($pref, $default_options)) {
                // finally use the property from RestAuth, if the
                // property exists as a default option:

//TODO: Convert values to correct types depending on gettype($default)
                $user->mOptions[$pref] = $value;
                $user->mOptionsOverrides[$pref] = $value;
            }
        }

        // update RestAuthRefreshTimestamp:
        $user->mOptions['RestAuthRefreshTimestamp'] = time();

        // begin saving the user to the local database:
        $user->setOption('echo-seen-time', $this->newTouchedTimestamp());

        // save user to the database:
        $user->saveSettings();
        wfDebug("-   END: " . __FUNCTION__ . "\n");
    }

    /**
      * Synchronize the local group database with the remote database.
      */
    public function refreshGroups(&$user) {
        wfDebug("- START: " . __FUNCTION__ . "\n");
        $user->load();
        $local_groups = $user->getGroups();
        $rest_groups = RestAuthGroup::getAll($this->conn, $user->getName());
        $remote_groups = array();
        foreach ($rest_groups as $rest_group) {
            $remote_groups[] = $rest_group->name;
        }

        # get database slave:
        $dbw = wfGetDB(DB_MASTER);

        # remove groups no longer found in the remote database:
        # NOTE: We do not call User::removeGroup here, because that would call the hook.
        #    If this whould be done, this would remove the group from the RestAuth server
        #    when loading groups from the RestAuth server, which doesn't make sense.
        $rem_groups = array_diff($local_groups, $remote_groups);
        foreach ($rem_groups as $group) {
            $dbw->delete('user_groups',
                array(
                    'ug_user'  => $user->getID(),
                    'ug_group' => $group,
                ),
                __METHOD__);
            // Remember that the user was in this group
                        $dbw->insert('user_former_groups',
                                array(
                                        'ufg_user'  => $user->getID(),
                                        'ufg_group' => $group,
                                ),
                                __METHOD__,
                                array('IGNORE'));
            $user->removedGroup($group);
        }

        # add new groups found in the remote database:
        # NOTE: We do not call User::addGroup here, because that would call the hook.
        #    If this whould be done, this would add the group at the RestAuth server
        #    when loading groups from the RestAuth server, which doesn't make sense.
        $add_groups = array_diff($remote_groups, $local_groups);
        foreach ($add_groups as $group) {
            if($user->getId()) {
                $dbw->insert('user_groups',
                    array(
                        'ug_user'  => $user->getID(),
                        'ug_group' => $group,
                    ),
                    __METHOD__,
                    array('IGNORE'));
            }
            $user->addGroup($group);
        }

        # reload cache
        $user->getGroups();
        $user->mRights = User::getGroupPermissions($user->getEffectiveGroups(true));
        wfDebug("-   END: " . __FUNCTION__ . "\n");
    }
    /**
     * Helper function to see if a =>preference is a global preference or not.
     */
    private function raPropertyName($option) {
        global $wgRestAuthGlobalProperties;

        if (array_key_exists($option, $wgRestAuthGlobalProperties) &&
                $wgRestAuthGlobalProperties[$option]) {
            return $option;
        } else {
            return 'mediawiki ' . $option;
        }
    }
}