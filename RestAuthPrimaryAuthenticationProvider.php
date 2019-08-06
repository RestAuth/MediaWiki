<?php
namespace MediaWiki\Auth;

use User;

/**
 * A primary authentication provider that authenticates the user against a RestAuth instance.
 *
 * @ingroup Auth
 * @since 1.27
 */
class RestAuthPrimaryAuthenticationProvider extends AbstractPrimaryAuthenticationProvider {

	public function continuePrimaryAuthentication( array $reqs ) {
		throw new \BadMethodCallException( __METHOD__ . ' is not implemented.' );
	}

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

	public function testForAccountCreation( $user, $creator, array $reqs ) {
	}

	public function continuePrimaryAccountCreation( $user, $creator, array $reqs ) {
		throw new \BadMethodCallException( __METHOD__ . ' is not implemented.' );
	}

	public function finishAccountCreation( $user, $creator, AuthenticationResponse $response ) {
	}

	public function postAccountCreation( $user, $creator, AuthenticationResponse $response ) {
	}

	public function testUserForCreation( $user, $autocreate, array $options = [] ) {
		return \StatusValue::newGood();
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

	public function beginPrimaryAccountCreation( $user, $creator, array $reqs ) {
	}

	public function getAuthenticationRequests( $action, array $options ) {
		switch ( $action ) {
			case AuthManager::ACTION_LOGIN:
				return [ new PasswordAuthenticationRequest() ];
			default:
				return [];
		}
	}

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

		// check for valid username & password
		// $req->username, $req->password
	}

	public function testUserExists( $username, $flags = User::READ_NORMAL ) {
	}

	public function providerAllowsAuthenticationDataChange( AuthenticationRequest $req, $checkData = true ) {
	}

	public function providerChangeAuthenticationData( AuthenticationRequest $req ) {
	}

	public function accountCreationType() {
		return self::TYPE_CREATE;
	}

}
