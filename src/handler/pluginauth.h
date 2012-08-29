#ifndef PLUGINAUTH_H
#define PLUGINAUTH_H

int check_plugin_auth(const char *version, const char *user, const char *timestamp, const char *token,
		      time_t now, long _auth_time_window, const char *url, const unsigned char *pw_hash);

#endif
