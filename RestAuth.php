<?php

// includes:
require_once('RestAuth/restauth.php' );
require_once(__DIR__ . '/RestAuthPlugin.php');
require_once(__DIR__ . '/RestAuthError.php');

$wgExtensionCredits['other'][] = array(
    'path' => __file__,
    'name' => 'RestAuth',
    'author' =>'Mathias Ertl',
    'url' => 'https://restauth.net/wiki/MediaWiki',
    'description' => 'RestAuth integration.',
);


$wgExtensionMessagesFiles['myextension'] = dirname( __FILE__ ) . '/RestAuth.i18n.php';

?>
