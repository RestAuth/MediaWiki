<?php
namespace MediaWiki\Auth;

use User;

use StatusValue;
use Message;

use MediaWiki\MediaWikiServices;
use MediaWiki\User\UserOptionsManager;

require_once('RestAuth/restauth.php');
require_once('RestAuthError.php');

use RestAuthConnection;
use RestAuthUser;
use RestAuthGroup;
use RestAuthResourceNotFound;
use RestAuthException;
use MWRestAuthError;

/**
 * A primary authentication provider that authenticates the user against a RestAuth instance.
 *
 * @ingroup Auth
 * @since 1.27
 */
class RestAuthPrimaryAuthenticationProvider extends AbstractPrimaryAuthenticationProvider {
    /* RestAuth variables */
    private static $wgRestAuthHost = 'localhost';

    /**
    * List of ignored =>preferences.
    *
    * This may either be an =>option or a =>setting, exactly as defined in
    * *MediaWiki*.
    */
    private static $wgRestAuthIgnoredPreferences = array(
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
    private static $wgRestAuthGlobalProperties = array(
        'language' => true,
        'full name' => true,
        'email' => true,
        'email confirmed' => true,
    );

    private static $wgRestAuthRefresh = 300;

    private static $preferenceMapping = array(
        // NOTE: 'full name' is a predefined property name.
        'mRealName' => 'full name',
        'email' => 'email',
        // email_confirmed is handled seperately - see below
    );

    private static $conn = null;

    public function __construct() {
        global $wgRestAuthHost;
        if (isset($wgRestAuthHost)) {
            self::$wgRestAuthHost = $wgRestAuthHost;
        }
    }

    /**
     * Verify that a user exists.
     */
    public function testUserExists( $username, $flags = User::READ_NORMAL ) {
        try {
            RestAuthUser::get(self::fnRestAuthGetConnection(), $username);
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
        global $wgLang;
        $req = AuthenticationRequest::getRequestByClass( $reqs, PasswordAuthenticationRequest::class );
        if ( !$req ) {
            return AuthenticationResponse::newAbstain();
        }

        if ( $req->username === null || $req->password === null ) {
            return AuthenticationResponse::newFail(new Message("username or password is null"));
        }

        $user = new RestAuthUser(self::fnRestAuthGetConnection(), $req->username);
        try {
            if ($user->verifyPassword($req->password)) {
                $user_cleaned = $wgLang->ucFirst($wgLang->lc($req->username));
                return AuthenticationResponse::newPass($user_cleaned);
            } else {
                return AuthenticationResponse::newAbstain();
                //return AuthenticationResponse::newFail(new Message("Username or Password failed."))
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
        $temp_auth_req = AuthenticationRequest::getRequestByClass( array($req), TemporaryPasswordAuthenticationRequest::class );
        if ( $auth_req || $temp_auth_req ) {
            return StatusValue::newGood();
        }
        return StatusValue::newFatal("this is no password authentication request (".get_class($req).") - perm");
    }

    /**
     * Actually do the password change
     */
    public function providerChangeAuthenticationData( AuthenticationRequest $req ) {
        $auth_req = AuthenticationRequest::getRequestByClass( array($req), PasswordAuthenticationRequest::class );
        $temp_auth_req = AuthenticationRequest::getRequestByClass( array($req), TemporaryPasswordAuthenticationRequest::class );
        if ( $auth_req ) {
            try {
                $user = new RestAuthUser(self::fnRestAuthGetConnection(), $req->username);
                $user->setPassword($req->password);
                return true;
            } catch (RestAuthException $e) {
                throw new MWRestAuthError($e);
            }
        } else if ( $temp_auth_req ) {
            return StatusValue::newGood( 'ignored' );
        }
        return StatusValue::newFatal("this is no password authentication request (".get_class($req).") - action");
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
        global $wgLang;
        if ($wgLang->ucFirst($wgLang->lc($user->getName())) != $user->getName()) {
            return StatusValue::newFatal("Please login with username in lowercase");
        }
        return StatusValue::newGood();
    }

    /**
     * second step of account creation: prevalidate the user
     */
    public function testForAccountCreation( $user, $creator, array $reqs ) {
        $req = AuthenticationRequest::getRequestByClass( $reqs, PasswordAuthenticationRequest::class );
        if ( $req ) {
            return StatusValue::newGood();
        }
        $temp_req = AuthenticationRequest::getRequestByClass( $reqs, TemporaryPasswordAuthenticationRequest::class );
        if ( $temp_req ){
            return StatusValue::newGood();
        }

        return StatusValue::newFatal("no Password Authentication Request found");
    }

    /**
     * third step of account creation: create the user
     */
    public function beginPrimaryAccountCreation( $user, $creator, array $reqs ) {
        // find the password auth request
        $auth_req = AuthenticationRequest::getRequestByClass( $reqs, PasswordAuthenticationRequest::class );
        $temp_auth_req = AuthenticationRequest::getRequestByClass( $reqs, TemporaryPasswordAuthenticationRequest::class );

        if ( !$auth_req && !$temp_auth_req ) {
            return AuthenticationResponse::newFail("no Password Authentication Request found");
        }

        if ( $temp_auth_req ) {
            $auth_req = $temp_auth_req;
        }

        // create an array of properties, if anything is present
        $properties = array();
        $email = $user->getEmail();
        $realname = $user->getRealName();
        if ($email) {
            $properties['email'] = $email;
        }
        if ($realname) {
            $properties['full name'] = $realname;
        }

        try {
            $name = $auth_req->username;
            if ( $temp_auth_req ) {
                $password = $auth_req->password.".invalid";
            } else {
                $password = $auth_req->password;
            }
            if (empty($properties)) {
                RestAuthUser::create(self::fnRestAuthGetConnection(), $name, $password);
            } else {
                RestAuthUser::create(
                    self::fnRestAuthGetConnection(), $name, $password, $properties);
            }

            if ( $temp_auth_req ) {
                return AuthenticationResponse::newAbstain();
            }

            return AuthenticationResponse::newPass();
        } catch (RestAuthException $e) {
            throw new MWRestAuthError($e);
        }

    }

    /**
     * fourth step of account creation: user has been added to the db
     */
    public function finishAccountCreation( $user, $creator, AuthenticationResponse $response ) {
        // call sync hook
        self::fnRestAuthLocalUserCreated($user, $autocreate = true);
        return StatusValue::newGood();
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
        return self::testUserExists( $username );
    }

    public function providerNormalizeUsername( $username ) {
        global $wgLang;
        $name = $wgLang->ucFirst($wgLang->lc($username));
        return $name === false ? null : $name;
    }

    public function providerRevokeAccessForUser( $username ) {
        $reqs = self::getAuthenticationRequests(
            AuthManager::ACTION_REMOVE, [ 'username' => $username ]
        );
        foreach ( $reqs as $req ) {
            $req->username = $username;
            $req->action = AuthManager::ACTION_REMOVE;
            self::providerChangeAuthenticationData( $req );
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
        if ( self::accountCreationType() === self::TYPE_LINK ) {
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

    public function continuePrimaryAuthentication( array $reqs ) {
        throw new \BadMethodCallException( __METHOD__ . ' is not implemented.' );
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
    public static function fnRestAuthUserNeedsRefresh($user) {
        $now = time();
        $userOptionsLookup = MediaWikiServices::getInstance()->getUserOptionsLookup();
        $timestamp = $userOptionsLookup->getIntOption($user, 'RestAuthRefreshTimestamp', $now);
        if ($timestamp + self::$wgRestAuthRefresh < $now) {
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
    public static function fnRestAuthRefreshCurrentUser($title, $article, $output, $user, $request, $mediaWiki) {
        if (!$user->isRegistered()) {
            return true;
        }

        $update = false;

        if ($title->isSpecial('Preferences') && $request->getMethod() === 'GET') {
            $update = true; // update when viewing Special:Preferences
        } else {

            // Update local database if the last refresh is more than
            // $wgRestAuthRefresh seconds ago:
            $update = self::fnRestAuthUserNeedsRefresh($user);
        }

        if ($update) {
            self::fnRestAuthUpdateUser($user);
        }

        return true;
    }

    /**
    * Called when a bureaucrat adds the user to a group via Special:UserRights.
    */
    public function fnRestAuthUserAddGroup($user, &$group) {
        if ($user->isSystemUser()) {
            return true;
        }

        $conn = self::fnRestAuthGetConnection();
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
    public function fnRestAuthUserRemoveGroup($user, &$group) {
        $conn = self::fnRestAuthGetConnection();
        $ra_group = new RestAuthGroup($conn, $group);
        try {
            $ra_group->removeUser($user->getName());
        } catch (RestAuthException $e) {
            //TODO: catch 404 if we're out of sync with the RestAuth server
            throw new MWRestAuthError($e);
        }
        return true;
    }

    /**
    * Helper function to get a connection object to the RestAuth service.
    */
    public static function fnRestAuthGetConnection() {
        global $wgRestAuthHost, $wgRestAuthService, $wgRestAuthServicePassword;
        if (! isset($wgRestAuthHost)) $wgRestAuthHost = 'http://localhost';

        if (self::$conn == null) {
            self::$conn = RestAuthConnection::getConnection($wgRestAuthHost,
            $wgRestAuthService, $wgRestAuthServicePassword);
        }

        return self::$conn;
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
    public static function fnRestAuthUpdateUser ($user) {
        # When a user logs in, optionally fill in preferences and such.
        self::refreshGroups($user);
        self::refreshPreferences($user);

        # reload everything
        $user->invalidateCache();
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
    public static function fnRestAuthUserSaveSettings($user) {
        wfDebug("- START: " . __FUNCTION__ . "($user)\n");

        if ($user->isSystemUser()) {
            return true;
        }

        $raUser = new RestAuthUser(self::fnRestAuthGetConnection(), $user->getName());
        $raProperties = $raUser->getProperties();

        // Properties are collected here and set in one single RestAuth call:
        $raSetProperties = array();
        $raDelProperties = array();

        // Handle =>settings.
        self::updateExternalDBSettings( $user, $raProperties, $raSetProperties,
            $raDelproperties);

        // Handle =>options.
        $userOptionsLookup = MediaWikiServices::getInstance()->getUserOptionsLookup();
        foreach($userOptionsLookup->getOptions($user) as $key => $value) {
            if (in_array($key, self::$wgRestAuthIgnoredPreferences)) {
                continue; // filter ignored options
            }
            self::_handleUpdateOption($raProperties, $key, $value,
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
    private static function updateExternalDBSettings ($user, $raProperties,
        &$raSetProperties, &$raDelProperties)
    {
        wfDebug("- START: " . __FUNCTION__ . "\n");

        if ($user->isSystemUser()) {
            return true;
        }

        foreach (self::$preferenceMapping as $prop => $raProp) {
            if (in_array($prop, self::$wgRestAuthIgnoredPreferences)) {
                continue; // filter ignored options
        }

        // hardcode email, as this is neither setting nor option
        $value = null;
        if ($raProp == "email") {
            $value = $user->getEmail();
        } else {
            $value = $user->$prop;
        }

        self::_handleUpdateSetting($raProperties, $raProp, $value,
            $raSetProperties);
        }

        // email confirmed is handled seperately, because locally its a boolean
        // value and we need to set '0' or '1' remotely (RestAuth properties
        // are always strings).

        // 'email confirmed' is prefixed if 'email' is prefixed.
        if (strpos(self::$preferenceMapping['email'], 'mediawiki ') === 0) {
            $raProp = 'mediawiki email confirmed';
        } else {
            $raProp = 'email confirmed';
        }

        if ($user->isEmailConfirmed()) {
            $value = '1';
        } else {
            $value = '0';
        }
        self::_handleUpdateSetting($raProperties, $raProp, $value,
            $raSetProperties);

        wfDebug("-   END: " . __FUNCTION__ . "\n");
    }

    private static function _handleUpdateSetting($raProperties, $raProp, $value,
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

    private static function _handleUpdateOption($raProperties, $option, $value,
            &$raSetProperties, &$raDelProperties)
    {
        $userOptionsLookup = MediaWikiServices::getInstance()->getUserOptionsLookup();
        $default = $userOptionsLookup->getDefaultOption($option);
        $raProp = self::raPropertyName($option);

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
     * Create a local user on import if the corresponding RestAuth user exists
     */
    public function fnRestAuthImportHandleUnknownUser($name) {
        // returns false if hook created a user
        // https://www.mediawiki.org/wiki/Manual:Hooks/ImportHandleUnknownUser
        $ra_user = new RestAuthUser(self::fnRestAuthGetConnection(), $name);
        if ($ra_user == null) {
            // continue with regular execution, hook did nothing
            return null;
        }
        $user = User::createNew($name);
        if ($user === null) {
            // continue with regular execution, hook did nothing
            return null;
        }
        // returning false means hook has been executed and an user has been created.
        // stop further processing for this hook
        return false;
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
    public static function fnRestAuthLocalUserCreated($user, $autocreate = false) {
        if ($user->isSystemUser()) {
            return;
        }

        if ($autocreate) {
            // true upon login and user doesn't exist locally
            self::refreshGroups($user);
            self::refreshPreferences($user);
        }
    }

    /**
     * =>Refresh =>preferences (=>settings AND =>options!) from RestAuth.
     */
    public static function refreshPreferences(&$user) {
        global $wgClockSkewFudge;
        // initialize local user:
        $user->load();
        if (wfReadOnly()) { return; }
        if (0 == $user->mId) { return; }
        wfDebug("- START: " . __FUNCTION__ . "\n");

        // get remote user:
        $ra_user = new RestAuthUser(self::fnRestAuthGetConnection(), $user->getName());

        // used as a complete list of all options:
        $userOptionsLookup = MediaWikiServices::getInstance()->getUserOptionsLookup();
        $default_options = $userOptionsLookup->getDefaultOptions();

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
                if (is_null(self::$wgRestAuthGlobalProperties) ||
                    !(array_key_exists($raProp, self::$wgRestAuthGlobalProperties)
                      && self::$wgRestAuthGlobalProperties[$raProp]))
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

            if (!is_null(self::$wgRestAuthIgnoredPreferences) && in_array($pref, self::$wgRestAuthIgnoredPreferences)) {
                continue; // filter ignored options
            }

            if ($pref == 'full name') {
                $user->setRealName($value);
            } elseif ($pref == 'email') {
                $user->setEmail($value);
            } elseif ($pref == 'email confirmed') {
                if ($value === '1') {
                    $user->confirmEmail();
                } else {
                    $user->invalidateEmail();
                }
            } elseif (array_key_exists($pref, $default_options)) {
                // finally use the property from RestAuth, if the
                // property exists as a default option:

                MediaWikiServices::getInstance()->getUserOptionsManager()->setOption($user, $pref, $value);
            }
        }

        // update RestAuthRefreshTimestamp:
        MediaWikiServices::getInstance()->getUserOptionsManager()->setOption($user, 'RestAuthRefreshTimestamp', time());

        // begin saving the user to the local database:
        MediaWikiServices::getInstance()->getUserOptionsManager()->setOption($user, 'echo-seen-time', wfTimestamp(TS_MW, time() + $wgClockSkewFudge));

        // save user to the database:
        $user->saveSettings();
        wfDebug("-   END: " . __FUNCTION__ . "\n");
    }

    /**
      * Synchronize the local group database with the remote database.
      */
    public static function refreshGroups(&$user) {
        $services = MediaWikiServices::getInstance();
        wfDebug("- START: " . __FUNCTION__ . "\n");
        $user->load();
        $local_groups = $user->getGroups();
        $rest_groups = RestAuthGroup::getAll(self::fnRestAuthGetConnection(), $user->getName());
        $remote_groups = array();
        foreach ($rest_groups as $rest_group) {
            $remote_groups[] = $rest_group->name;
        }

        # get database slave:
        $dbw = wfGetDB(DB_MASTER);

        # remove groups no longer found in the remote database
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
            $services->getUserGroupManager()->removeUserFromGroup($user, $group);
        }

        # add new groups found in the remote database
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
            $services->getUserGroupManager()->addUserToGroup($user, $group);
        }

        # reload cache
        $user->getGroups();
        $services->getPermissionManager()->getUserPermissions($user);
        wfDebug("-   END: " . __FUNCTION__ . "\n");
    }
    /**
     * Helper function to see if a =>preference is a global preference or not.
     */
    private static function raPropertyName($option) {
        if (array_key_exists($option, self::$wgRestAuthGlobalProperties) &&
                self::$wgRestAuthGlobalProperties[$option]) {
            return $option;
        } else {
            return 'mediawiki ' . $option;
        }
    }
}
