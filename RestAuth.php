<?php

global $wgRestAuthIgnoredOptions, $wgRestAuthGlobalOptions;
// default settings;
if ( ! $wgRestAuthHost ) $wgRestAuthHost = 'localhost';
if ( ! $wgRestAuthIgnoredOptions ) {
	$wgRestAuthIgnoredOptions = array(
		"watchlisttoken",
	);
}

if ( $wgRestAuthGlobalOptions ) {
	if ( ! array_key_exists( 'language', $wgRestAuthGlobalOptions ) )
		$wgRestAuthGlobalOptions['language'] = true;
		$wgRestAuthGlobalOptions['real name'] = true;
		$wgRestAuthGlobalOptions['email'] = true;
		$wgRestAuthGlobalOptions['email confirmed'] = true;
} else {
	// default, if not set at all
	$wgRestAuthGlobalOptions = array(
		'language' => true,
		'real name' => true,
		'email' => true,
		'email confirmed' => true,
	);
}

// includes:
require_once( '/usr/share/php-restauth/restauth.php' );
require_once( dirname(__FILE__) . '/RestAuthPlugin.php' );
require_once( dirname(__FILE__) . '/RestAuthError.php' );

$wgExtensionCredits['other'][] = array(
	'name' => 'RestAuth',
	'author' =>'Mathias Ertl',
	'url' => 'http://fs.fsinf.at/wiki/RestAuth_(MediaWiki_extension)', 
	'description' => 'RestAuth integration.',
);


$wgExtensionMessagesFiles['myextension'] = dirname( __FILE__ ) . '/RestAuth.i18n.php';

?>
