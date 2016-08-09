# NetWatcher daemon

Waits for IPv4 or IPv6 address changes on any interface.

Executes a utility (default ~/.netwatch) when an IP change is
detected.

Only works on OS X.


# Building

Run `make`. There are no dependencies.


# Using NetWatcher

Usage: netwatcher [-qd] [-EO] [-e|-o] [-f UTILITY ]  
 -q: quiet mode  
 -d: debug mode, stay in foreground  
 -E: close UTILITY's stderr  
 -O: close UTILITY's stdout  
 -e: redirect UTILITY's stdout to stderr  
 -o: redirect UTILITY's stderr to stdout

NetWatcher will attempt to not execute UTILITY if it is already
running, but will instead note that UTILITY should be run again if a
change arrives while it is still running. If this happens enough
times without UTILITY exiting, NetWatcher will get increasingly
aggressive about killing the last invocation of UTILITY so that it can
invoke it again.

If no UTILITY is specified, NetWatcher will `chdir` to the current
user's home directory and set UTILITY to `./.netwatch`


# Bugs

NetWatcher uses `daemon(3)` which is deprecated. Launchd support
patches welcome.

NetWatcher is verbose by default.


# Authorship/Licence

This code is derived from Jeremy Friesner's public domain IP change
detection code at:  
https://public.msli.com/lcs/jaf/osx_ip_change_notify.cpp

Which in turn derives from:  
http://developer.apple.com/technotes/tn/tn1145.html

The changes made Eric Kobrin are hereby released as CC0 1.0 (Public
Domain)  
https://creativecommons.org/publicdomain/zero/1.0/
