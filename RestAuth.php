<?php
require_once( '/usr/share/php-restauth/restauth.php' );
require_once( dirname(__FILE__) . '/RestAuthPlugin.php' );

$wgExtensionCredits['other'][] = array(
	'name' => 'RestAuth',
	'author' =>'Mathias Ertl',
	'url' => 'http://fs.fsinf.at/wiki/RestAuth_(MediaWiki_extension)', 
	'description' => 'RestAuth integration.',
);


$wgExtensionMessagesFiles['myextension'] = dirname( __FILE__ ) . '/RestAuth.i18n.php';
?>
