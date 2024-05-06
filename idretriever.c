/*
 *  Copyright (c) 2024 Filippo Rossoni
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <config.h>

#include "openconnect-internal.h"

#include <ctype.h>

static const char response_404[] = "HTTP/1.1 404 Not Found\r\n"
		"Connection: close\r\n"
		"Content-Type: text/html\r\n"
		"Content-Length: 0\r\n\r\n";


static const char response_200[] = "HTTP/1.1 200 OK\r\n"
		"Connection: close\r\n"
		"Content-Type: text/html\r\n\r\n"
		"<html><title>Success</title><body>Success</body></html>\r\n";

//copied from hpke.c find a way to reuse that is compatible with all build
#ifdef HAVE_POSIX_SPAWN
static int spawn_browser(struct openconnect_info *vpninfo)
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
static int spawn_browser(struct openconnect_info *vpninfo)
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


int listen_for_id(struct openconnect_info *vpninfo, uint16_t listen_port) {
	int ret = 0;

	struct sockaddr_in6 sin6;
	bzero((char*) &sin6, sizeof(sin6));
	sin6.sin6_family = AF_INET;
	sin6.sin6_port = htons(listen_port);
	sin6.sin6_addr = in6addr_loopback;

	int listen_fd;
#ifdef SOCK_CLOEXEC
	listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
	if (listen_fd < 0)
#endif
		listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (listen_fd < 0) {
		char *errstr;
		sockerr:
#ifdef _WIN32
	errstr = openconnect__win32_strerror(WSAGetLastError());
#else
		errstr = strerror(errno);
#endif
		vpn_progress(vpninfo, PRG_ERR,
				_("Failed to listen on local port 29786: %s\n"), errstr);
#ifdef _WIN32
	free(errstr);
#endif
		if (listen_fd >= 0)
			closesocket(listen_fd);
		return -EIO;
	}
	int optval = 1;
	(void) setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (void*) &optval,
			sizeof(optval));

	if (bind(listen_fd, (void*) &sin6, sizeof(sin6)) < 0)
		goto sockerr;

	if (listen(listen_fd, 1))
		goto sockerr;

	if (set_sock_nonblock(listen_fd))
		goto sockerr;

	//set sso-login
	char requestUrl[256];
	snprintf(requestUrl, sizeof(requestUrl), "https://%s:%d/%s",
			vpninfo->hostname, vpninfo->port,vpninfo->urlpath);
	free(vpninfo->sso_login);
	vpninfo->sso_login = strdup(requestUrl);

	/* Now that we are listening on the socket, we can spawn the browser */
		if (vpninfo->open_ext_browser) {
			ret = vpninfo->open_ext_browser(vpninfo, vpninfo->sso_login, vpninfo->cbdata);
	#if defined(HAVE_POSIX_SPAWN) || defined(_WIN32)
		} else if (vpninfo->external_browser) {
			ret = spawn_browser(vpninfo);
	#endif
		} else {
			ret = -EINVAL;
		}
		if (ret)
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to spawn external browser for %s\n"),
				     vpninfo->sso_login);


	char *retid = NULL;

	/* There may be other stray connections. Repeat until we have one
	 * that looks like the actual auth attempt from the browser. */
	while (1) {
		int accept_fd = cancellable_accept(vpninfo, listen_fd);
		if (accept_fd < 0) {
			ret = accept_fd;
			goto out;
		}
		vpn_progress(vpninfo, PRG_TRACE,
				_("Accepted incoming external-browser connection on port 8020\n"));
		char line[4096];
		ret = cancellable_gets(vpninfo, accept_fd, line, sizeof(line));
		if (ret < 15 || strncmp(line, "GET /", 5)
				|| strncmp(line + ret - 9, " HTTP/1.", 8)) {
			vpn_progress(vpninfo, PRG_TRACE,
					_("Invalid incoming external-browser request\n"));
			closesocket(accept_fd);
			continue;
		}
		if (strncmp(line, "GET /", 5)) {
			give_404: cancellable_send(vpninfo, accept_fd, response_404,
					sizeof(response_404) - 1);
			closesocket(accept_fd);
			continue;
		}

		/*
		 * OK, now we have a "GET /api/sso/… HTTP/1.x" that looks sane.
		 * Kill the " HTTP/1.x" at the end.
		 * */
		line[ret - 9] = 0;

		/* Scan for ?id= (and other params that shouldn't be there) */
		char *id = line + 5;
		char *q = strchr(id, '?');
		while (q) {
			*q = 0;
			q++;
			if (!strncmp(q, "id=", 3))
				retid = q + 3;
			q = strchr(q, '&');
		}
		/* Store the retid (since we'll reuse the line buf) */
		if (retid) {
			//no need to decode used in a url
			//urldecode_inplace(retid);
			retid = strdup(retid);
		}

		/* Now consume the rest of the HTTP request lines */
		while (cancellable_gets(vpninfo, accept_fd, line, sizeof(line)) > 0) {
			vpn_progress(vpninfo, PRG_DEBUG, "< %s\n", line);
		}

		/* Finally, send the response to redirect to the success page */
		if (retid) {
			ret = cancellable_send(vpninfo, accept_fd, response_200,
					sizeof(response_200) - 1);
		}else{
			goto give_404;
		}
		closesocket(accept_fd);
		if (ret < 0)
			goto out;

		break;

	}
	vpn_progress(vpninfo, PRG_DEBUG, _("Got  Id %s \n"), retid);

	char authUrl[256];
	snprintf(authUrl, sizeof(authUrl) - 1, "remote/saml/auth_id?id=%s", retid);
	free(vpninfo->urlpath);
	vpninfo->urlpath = strdup(authUrl);

	out:
	free(retid);
	closesocket(listen_fd);
	return ret;

}
