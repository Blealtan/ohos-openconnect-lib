/*
 * spawn-browser.c
 *
 *  Created on: 21 giu 2024
 *      Author: filippor
 */
#include <config.h>
#include "openconnect-internal.h"
#include <ctype.h>

#ifdef HAVE_POSIX_SPAWN
int spawn_browser(struct openconnect_info *vpninfo)
{
	vpn_progress(vpninfo, PRG_TRACE, _("Spawning external browser '%s'\n"),
		     vpninfo->external_browser);

	int ret = 0;
	pid_t pid = 0;
	char *browser_argv[3] = { (char *)vpninfo->external_browser, vpninfo->sso_login, NULL };
	posix_spawn_file_actions_t file_actions, *factp = NULL;

	if (!posix_spawn_file_actions_init(&file_actions)) {
		factp = &file_actions;
		posix_spawn_file_actions_adddup2(&file_actions, STDERR_FILENO, STDOUT_FILENO);
	}

	if (posix_spawn(&pid, vpninfo->external_browser, factp, NULL, browser_argv, environ)) {
		ret = -errno;
		vpn_perror(vpninfo, _("Spawn browser"));
	}
	if (factp)
		posix_spawn_file_actions_destroy(factp);

	return ret;
}
#elif defined(_WIN32)
int spawn_browser(struct openconnect_info *vpninfo)
{
	HINSTANCE rv;
	char *errstr;

	vpn_progress(vpninfo, PRG_TRACE, _("Spawning external browser '%s'\n"),
		     vpninfo->external_browser);

	rv = ShellExecute(NULL, vpninfo->external_browser, vpninfo->sso_login,
			  NULL, NULL, SW_SHOWNORMAL);

	if ((intptr_t)rv > 32)
		return 0;

	errstr = openconnect__win32_strerror(GetLastError());
	vpn_progress(vpninfo, PRG_ERR, "Failed to spawn browser: %s\n",
		     errstr);
	free(errstr);
	return -EIO;
}
#endif
