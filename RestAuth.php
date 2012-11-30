<?php

// includes:
require_once('RestAuth/restauth.php' );
require_once(dirname(__FILE__) . '/RestAuthPlugin.php');
require_once(dirname(__FILE__) . '/RestAuthError.php');

$wgExtensionCredits['other'][] = array(
	'name' => 'RestAuth',
	'author' =>'Mathias Ertl',
	'url' => 'https://restauth.net/wiki/MediaWiki',
	'description' => 'RestAuth integration.',
);


$wgExtensionMessagesFiles['myextension'] = dirname( __FILE__ ) . '/RestAuth.i18n.php';

?>
