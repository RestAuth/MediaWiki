TODO
====

* ``Special:Userrights`` has a hook for when groups are changed, but not when
  they are first viewed. Hence the initial view might be out of date.

* disable LocalPasswordPrimaryAuthenticationProvider:
  AuthPlugin::allowSetLocalPassword() has no direct replacement. If the wiki's
  sysadmin wants to disallow setting passwords in the user table, they can
  either not use LocalPasswordPrimaryAuthenticationProvider or configure it
  with loginOnly = true.
