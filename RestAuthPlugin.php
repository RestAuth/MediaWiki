<?php

require_once("$IP/includes/AuthPlugin.php");
require_once('RestAuth/restauth.php');

# group handling:
$wgHooks['UserAddGroup'][] = 'fnRestAuthUserAddGroup';
$wgHooks['UserRemoveGroup'][] = 'fnRestAuthUserRemoveGroup';
$wgHooks['UserRights'][] = 'fnRestAuthUserRights';

# auto-update local database
$wgHooks['BeforeInitialize'][] = 'fnRestAuthUpdateFromRestAuth';

// default settings;
if (! isset($wgRestAuthHost)) $wgRestAuthHost = 'localhost';
$wgRestAuthIgnoredOptions = array(
    "RestAuthRefreshTimestamp",
    "watchlisttoken",
);

// default, if not set at all
$wgRestAuthGlobalOptions = array(
    'language' => true,
    'full name' => true,
    'email' => true,
    'email confirmed' => true,
);
$wgRestAuthRefresh = 300;

/**
 * This function is called upon every pageview and refreshes the local database
 * cache if the last refresh is more than $RestAuthRefresh seconds ago or we are on
 * Special:Preferences.
 *
 * Please see the documentation for the BeforeInitialize Hook if needed.
 */
function fnRestAuthUpdateFromRestAuth($title, $article, $output, $user, $request, $this) {
    if (!$user->isLoggedIn()) {
        return true;
    }

    $update = false;

    if ($title->getNamespace() === NS_SPECIAL
            && SpecialPage::resolveAlias($title->getText()) === "Preferences"
            && $request->getMethod() === 'GET')
    {
        $update = true; // update when viewing Special:Preferences
    } else {
        global $wgRestAuthRefresh;

        // Update local database if the last refresh is more than
        // $wgRestAuthRefresh seconds ago:
        $now = time();
        $timestamp = $user->getIntOption('RestAuthRefreshTimestamp', $now);
        if ($timestamp + $wgRestAuthRefresh < $now) {
            $update = true;
        }
    }

    if ($update) {
        global $wgAuth;
        $wgAuth->updateUser($user);
    }

    return true;
}

/**
 * UserRights.
 *
 * This Hook should replace UserAddGroup and UserRemoveGroup, once all calles
 * to User::addGroup and User::removeGroup are supplemented by this hook.
 */
function fnRestAuthUserRights(&$user, $add, $remove) {
    return true;
}


/**
 * Called when a bureaucrat adds the user to a group via Special:UserRights.
 */
function fnRestAuthUserAddGroup($user, $group) {
    $conn = fnRestAuthGetConnection();
    $ra_group = new RestAuthGroup($conn, $group);
    try {
        $ra_group->addUser($user->getName());
//TODO: catch 404 if we're out of sync with the RestAuth server
    } catch (RestAuthException $e) {
        throw new MWRestAuthError($e);
    }
    return true;
}

/**
 * Called when a bureaucrat removes a group from a user via Special:UserRights.
 */
function fnRestAuthUserRemoveGroup($user, $group) {
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

class RestAuthPlugin extends AuthPlugin {
    public function __construct() {
        $this->conn = fnRestAuthGetConnection();

        $this->settingsMapping = array(
            // NOTE: 'full name' is a predefined property name.
            'mRealName' => $this->raOptionName('full name'),
            'email' => $this->raOptionName('email'),
            // email_confirmed is handled seperately - see below
        );
    }

    /**
     * Verify that a user exists.
     */
    public function userExists ($username) {
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
    public function authenticate ($username, $password) {
        $user = new RestAuthUser($this->conn, $username);
        try {
            if ($user->verifyPassword($password)) {
                return true;
            } else {
                return false;
            }
        } catch (RestAuthException $e) {
            throw new MWRestAuthError($e);
        }
    }

/*    function modifyUITemplate (&$template, &$type) {
        # Modify options in the login template.
    }
*/
/*    function setDomain ($domain) {
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

    private function newTouchedTimestamp() {
        global $wgClockSkewFudge;
        return wfTimestamp(TS_MW, time() + $wgClockSkewFudge);
    }

    /**
     * Called whenever a user logs in. It updates local groups to mach those
     * from the remote database.
     *
     * Also called by fnRestAuthUpdateFromRestAuth (which registers the
     * BeforeInitialize-Hook), if the user views Special:Preferences or
     * $wgRestAuthRefresh seconds have passed since the last synchronization.
     */
    public function updateUser (&$user) {
        wfDebug("- START: " . __FUNCTION__ . "($user)\n");
        # When a user logs in, optionally fill in preferences and such.
        $this->refreshUserGroupsFromRestAuth($user);
        $this->refreshUserSettingsFromRestAuth($user);

        # reload everything
        $user->invalidateCache();
        wfDebug("-   END: " . __FUNCTION__ . "\n");
    }

    public function autoCreate () {
        # Return true if the wiki should create a new local account
        # automatically when asked to login a user who doesn't exist
        # locally but does in the external auth database.
        return true;
    }

/*    function allowPropChange ($prop= '') {
        # Allow a property change? Properties are the same as
        # preferences and use the same keys.
    }
*/
    public function allowPasswordChange () {
        return true;
    }

    public function setPassword ($user, $password) {
        wfDebug("- START: " . __FUNCTION__ . "\n");
        try {
            $user = new RestAuthUser($this->conn, $user->getName());
            $user->setPassword($password);
            wfDebug("-   END: " . __FUNCTION__ . "\n");
            return true;
        } catch (RestAuthException $e) {
            wfDebug("-   EXP: " . __FUNCTION__ . "\n");
            throw new MWRestAuthError($e);
        }
    }

    /**
     * See https://bugzilla.wikimedia.org/show_bug.cgi?id=49641
     */
    public function updateExternalDBGroups ($user, $addgroups, $delgroups) {
        return true;
    }

    /**
     * Update the external user database.
     *
     * This is called when the user hits 'submit' on Special:Preferences. This
     * function is better then implementing Hooks provided by User::save,
     * because then there is no way to save the local user WITHOUT updating
     * the external database.
     */
    public function updateExternalDB ($user) {
        wfDebug("- START: " . __FUNCTION__ . "($user)\n");
        global $wgRestAuthIgnoredOptions;

        $raUser = new RestAuthUser($this->conn, $user->getName());
        $raProperties = $raUser->getProperties();

        // Properties are collected here and set in one single RestAuth call:
        $raSetProperties = array();
        $raDelProperties = array();

        // In MediaWiki, settings (as opposed to "options") are stored directly
        // in the user table and are properties of a User instance (e.g.
        // $user->email). Options are handled below.
        $this->updateSettingsToExternalDB(
            $raProperties, $raSetProperties, $raDelproperties);


        // Finally handle options (which are in a seperate option table in
        // MediaWiki)

        foreach($user->getOptions() as $key => $value) {
            if (in_array($key, $wgRestAuthIgnoredOptions)) {
                continue; // filter ignored options
            }
            $this->_handleSaveOption($raProperties, $key, $value,
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

            foreach($raDelProperties as $raProp) {
                wfDebug("----- Del '$raProp'\n");
                $raUser->removeProperty($raProp);
            }

            wfDebug("-   END: fnRestAuthSaveSettings\n");
            return true;
        } catch (RestAuthException $e) {
            wfDebug("- EXCEPTION: fnRestAuthSaveSettings - $e\n");
            throw new MWRestAuthError($e);
        }
    }

    public function updateSettingsToExternalDB ($raProperties,
        &$raSetProperties, &$raDelProperties)
    {
        wfDebug("- START: " . __FUNCTION__ . "\n");
        foreach ($this->settingsMapping as $prop => $raProp) {
            if (in_array($key, $wgRestAuthIgnoredOptions)) {
                continue; // filter ignored options
            }

            $this->_handleSaveSetting($raProperties, $raProp, $user->$prop,
                $raSetProperties);
        }

        // email confirmed is handled seperately, because locally its a boolean
        // value and we need to set '0' or '1' remotely (RestAuth properties
        // are always strings).

        // 'email confirmed' is prefixed if 'email' is prefixed.
        if (strpos($this->settingsMapping['email'], 'mediawiki ') === 0) {
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
        $this->_handleSaveSetting($raProperties, $raProp, $value,
            $raSetProperties);

        wfDebug("-   END: " . __FUNCTION__ . "\n");
    }

    private function _handleSaveSetting($raProperties, $raProp, $value,
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

    private function _handleSaveOption($raProperties, $key, $value,
            &$raSetProperties, &$raDelProperties)
    {
        $default = User::getDefaultOption($key);
        $raProp = $this->raOptionName($key);

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

    public function canCreateAccounts () {
        /**
         * Always returns true
         */
        return true;
    }

    /**
     * Add a user to the external authentication database.
     *
     * Called when creating a new user - before it exists in the local
     * database.
     */
    public function addUser ($user, $password, $email= '', $realname= '') {
        wfDebug("- START: " . __FUNCTION__ . "\n");

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
            return true;
        } catch (RestAuthException $e) {
            throw new MWRestAuthError($e);
        }
    }

    /**
     * Update a user from RestAuth. This is called when a new user was created
     * ($autocreate=false) or when a user logs in and doesn't yet exist
     * locally ($autocreate=true).
     */
    public function initUser (&$user, $autocreate) {
        wfDebug("- START: " . __FUNCTION__ . "\n");
        if ($autocreate) {
            wfDebug("--- User is autocreated - syncing.\n");
            // true upon login and user doesn't exist locally
            $this->refreshUserGroupsFromRestAuth($user);
            $this->refreshUserSettingsFromRestAuth($user);
        }
        wfDebug("-   END: " . __FUNCTION__ . "\n");
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

/*    function getCanonicalName ($username) {
        # If you want to munge the case of an account name before the
        # final check, now is your chance.
    }
*/
/*    function getUserInstance (User &$user) {
        # Get an instance of a User object.
    }
 */

    /**
     * Should MediaWiki store passwords in its local database?
     */
    public function allowSetLocalPassword() {
        return false;
    }

    /**
     * Update local settings from RestAuth.
     *
     * This function saves settings to the database.
     */
    public function refreshUserSettingsFromRestAuth(&$user) {
        // initialize local user:
        $user->load();
        if (wfReadOnly()) { return; }
        if (0 == $user->mId) { return; }
        wfDebug("- START: " . __FUNCTION__ . "\n");

        // get remote user:
        global $wgRestAuthIgnoredOptions, $wgRestAuthGlobalOptions;
        $ra_user = new RestAuthUser($this->conn, $user->getName());

        // used as a complete list of all options:
        $default_options = User::getDefaultOptions();

        // get all options from the RestAuth service
        try {
            $rest_options = $ra_user->getProperties();
        } catch (RestAuthException $e) {
            // if this is the case, we just don't load any options.
            wfDebug("Unable to get options from auth-service: " . $e . "\n");
            return;
        }

        // take care of setting all settings and options to the current
        // user object.
        foreach($rest_options as $key => $value) {
            if (strpos($key, 'mediawiki ') === 0) {
                // if this is a mediawiki specific setting, remove the
                // prefix:
                $prop_name = substr($key, 10);
            } else {
                // This setting is not specific to MediaWiki. Only use
                // the setting if we find it in $wgRestAuthGlobalOptions.
                if (is_null($wgRestAuthGlobalOptions) ||
                    !(array_key_exists($key, $wgRestAuthGlobalOptions)
                      && $wgRestAuthGlobalOptions[$key]))
                {
                    continue;
                }

                // This is a global option where we also have an option
                // specific to MediaWiki - which we use instead
                if (array_key_exists('mediawiki ' . $key, $rest_options)) {
                    continue;
                }
                $prop_name = $key;
            }

            if (!is_null($wgRestAuthIgnoredOptions) && in_array($prop_name, $wgRestAuthIgnoredOptions)) {
                continue; // filter ignored options
            }

            if ($prop_name == 'full name') {
                $user->mRealName = $value;
            } elseif ($prop_name == 'email') {
                $user->mEmail = $value;
            } elseif ($prop_name == 'email confirmed') {
//TODO: Set to true or false depending on value
                $user->mEmailConfirmed = $value;
            } elseif (array_key_exists($prop_name, $default_options)) {
                // finally use the property from RestAuth, if the
                // property exists as a default option:

//TODO: Convert values to correct types depending on gettype($default)
                $user->mOptions[$prop_name] = $value;
                $user->mOptionsOverrides[$prop_name] = $value;
            }
        }

        // update RestAuthRefreshTimestamp:
        $user->mOptions['RestAuthRefreshTimestamp'] = time();

        // begin saving the user to the local database:
        $user->mTouched = self::newTouchedTimestamp();

        // save user to the database:
        $user->saveSettings();
        wfDebug("-   END: " . __FUNCTION__ . "\n");
    }

    /**
      * Synchronize the local group database with the remote database.
      */
    public function refreshUserGroupsFromRestAuth(&$user) {
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
            $user->mGroups = array_diff($user->mGroups, array($group));
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
            $user->mGroups[] = $group;
        }

        # reload cache
        $user->getGroups();
        $user->mRights = User::getGroupPermissions($user->getEffectiveGroups(true));
        wfDebug("-   END: " . __FUNCTION__ . "\n");
    }
    /**
     * Helper function to see if an option is a global option or not.
     */
    private function raOptionName($option) {
        global $wgRestAuthGlobalOptions;

        if (array_key_exists($option, $wgRestAuthGlobalOptions) &&
                $wgRestAuthGlobalOptions[$option]) {
            return $option;
        } else {
            return 'mediawiki ' . $option;
        }
    }
}
