<?php

$messages = array();
$messages['en'] = array(
	'restauthexception-header' => 'Generic RestAuth exception',
	'restauthexception-body' => 'This statement should never be thrown. Please contact the administrators of this Wiki.',
	'restauthdataunacceptable-header' => 'Data unacceptable', // Note: Caught in the appropriate place
	'restauthdataunacceptable-body' => 'This statement should never be visible to you. Please contact the administrators of this Wiki.',

	// internal exceptions
	'restauthinternalexception-header' => 'Authentication server temporarily unavailable',
	'restauthinternalexception-body' => 'The authentication server temporarily unavailable. Please try again later.',
	'restauthbadrequest-header' => 'Authentication server temporarily unavailable',
	'restauthbadrequest-body' => 'The authentication server was unable to parse the request. Please try again later.',
	'restauthinternalservererror-header' => 'Authentication server temporarily unavailable',
	'restauthinternalservererror-body' => 'The authentication server suffers from internal problems. Please try again later.',
	'restauthunknownstatus-header' => 'Authentication server temporarily unavailable',
	'restauthunknownstatus-body' => 'The authentication server responded with an unknown status code. Please try again later.',

	// Resource Conflicts:
	'restauthuserexists-header' => 'User already exists',
	'restauthuserexists-body' => 'A user with this name already exists.',
	'restauthpropertyexists-header' => 'Property already exists',
	'restauthpropertyexists-body' => 'A property with this name already exists.',
	'restauthgroupexists-header' => 'Group already exists',
	'restauthgroupexists-body' => 'A group with this name already exists.',

	// Resource not found:
	'restauthusernotfound-header' => 'User not found.',
	'restauthusernotfound-body' => 'No user with the specified username was found.',
	'restauthpropertynotfound-header' => 'Property not found.',
	'restauthpropertynotfound-body' => 'The specified property was not found.',
	'restauthgroupnotfound-header' => 'User not found.',
	'restauthgroupnotfound-body' => 'The specified group was not found.',

	
	'restauthunauthorized-header' => 'Cannot contact the authentication service',
	'restauthunauthorized-body' => 'The Wiki was unable to contact the authentication server because this Wiki is unknown to it. 

If you are the system administrator, please check $wgRestAuthHost, $wgRestAuthPort, $wgRestAuthService and $wgRestAuthServicePassword are correct.',
);
