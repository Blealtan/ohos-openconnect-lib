/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2020-2021 Andreas Gnau, Daniel Lenski
 *
 * Author: Andreas Gnau <rondom@rondom.de>, Daniel Lenski <dlenski@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include <config.h>

#include <ctype.h>
#include <errno.h>
#include <libxml/HTMLparser.h>
#include <libxml/HTMLtree.h>

#include "openconnect-internal.h"

static char const ipv4_default_route[] = "0.0.0.0/0.0.0.0";
static char const ipv6_default_route[] = "::/0";

static struct nx_proto_data *reset_nx_proto_data(struct openconnect_info *vpninfo)
{
	memset(&vpninfo->proto_data.nx, 0, sizeof(vpninfo->proto_data.nx));
	vpninfo->proto_data.nx.password_expiration_days = INT_MIN;
	return &vpninfo->proto_data.nx;
}

static int nx_header_cb(struct openconnect_info *vpninfo, char *header, char *value)
{
	struct nx_proto_data *nx_response = &vpninfo->proto_data.nx;
	if (!strcmp(header, "X-NE-message")) {
		nx_response->message = strdup(value);
		if (!nx_response->message)
			return 1;
	} else if (!strcmp(header, "X-NE-pwdexpdays"))
		nx_response->password_expiration_days = atoi(value);
	else if (!strcmp(header, "X-NE-maychangepwd"))
		nx_response->may_change_password = 1;
	else if (!strcmp(header, "X-NE-tf")) {
		if (!strcmp(value, "1"))
			nx_response->token_auth = 1;
	} else if (!strcmp(header, "X-NE-saml")) {
		if (!strcmp(value, "authType:SAML"))
			nx_response->saml_auth = 1;
	} else if (!strcmp(header, "X-NE-pda"))
		nx_response->pda = 1;
	else if (!strncmp(header, "X-NE-", 5)) {
		vpn_progress(vpninfo, PRG_INFO, _("Unknown header %s.\n"), header);
		vpn_progress(vpninfo, PRG_INFO, _("Please report this to <openconnect-devel@lists.infradead.org>.\n"));
	}
	return 0;
}

static int store_cookie_if_valid(struct openconnect_info *vpninfo)
{
	struct oc_vpn_option *cookie;
	struct oc_text_buf *buf;
	int ret = 1;

	for (cookie = vpninfo->cookies; cookie; cookie = cookie->next) {
		if (strcmp(cookie->option, "swap") == 0) {
			buf = buf_alloc();
			buf_append(buf, "%s", cookie->value);
			if (!buf_error(buf)) {
				vpninfo->cookie = buf->data;
				buf->data = NULL;
				ret = 0;
			}
			buf_free(buf);
		}
	}
	return ret;
}

int nx_obtain_cookie(struct openconnect_info *vpninfo)
{
	int ret;
	struct oc_text_buf *resp_buf = NULL;
	xmlDocPtr doc = NULL;
	xmlNodePtr node;
	struct oc_auth_form *form = NULL;
	char *form_id = NULL;

	resp_buf = buf_alloc();
	if (buf_error(resp_buf)) {
		ret = buf_error(resp_buf);
		goto out;
	}
	vpninfo->urlpath = strdup("cgi-bin/welcome");
	while (1) {
		char *form_buf = NULL;
		struct oc_text_buf *url;
		struct nx_proto_data *nx_response = reset_nx_proto_data(vpninfo);
		if (resp_buf && resp_buf->pos)
			ret = do_https_request(vpninfo, "POST", "application/x-www-form-urlencoded", resp_buf,
					       &form_buf, nx_header_cb, 0);
		else
			ret = do_https_request(vpninfo, "GET", NULL, NULL, &form_buf, nx_header_cb, 0);

		/* In case of SAML, we get Content-Length: 0 and status 200,
		 * which should not be an issue, but do_https_request errors
		 * in this case. Not sure, if that is intended behaviour.
		 */
		if (ret < 0 && !nx_response->saml_auth)
			break;

		if (nx_response->token_auth) {
			vpn_progress(vpninfo, PRG_ERR, _("NetExtender OTP authentication is not supported, yet.\n"));
			vpn_progress(vpninfo, PRG_INFO,
				     _("Please report this to <openconnect-devel@lists.infradead.org>.\n"));
			ret = -EINVAL;
			break;
		}
		if (nx_response->saml_auth) {
			vpn_progress(vpninfo, PRG_ERR, _("NetExtender SAML authentication is not supported, yet.\n"));
			vpn_progress(vpninfo, PRG_INFO,
				     _("Please report this to <openconnect-devel@lists.infradead.org>.\n"));
			ret = -EINVAL;
			break;
		}
		if (nx_response->password_expiration_days != INT_MIN)
			vpn_progress(vpninfo, PRG_INFO, _("Password expires in %d days.\n"),
				     nx_response->password_expiration_days);
		if (nx_response->may_change_password)
			vpn_progress(vpninfo, PRG_INFO, _("Server reports that changing the password is possible.\n"));
		if (nx_response->pda) {
			vpn_progress(vpninfo, PRG_INFO,
				     _("NetExtender PDA (Personal Device Authorization) is not fully supported.\n"));
			vpn_progress(vpninfo, PRG_INFO,
				     _("Please report this to <openconnect-devel@lists.infradead.org>.\n"));
		}
		if (nx_response->message) {
			vpn_progress(vpninfo, PRG_ERR, "Message from server: %s\n", nx_response->message);
			ret = -EINVAL;
			break;
		}

		url = buf_alloc();
		buf_append(url, "https://%s", vpninfo->hostname);
		if (vpninfo->port != 443)
			buf_append(url, ":%d", vpninfo->port);
		buf_append(url, "/");
		if (vpninfo->urlpath)
			buf_append(url, "%s", vpninfo->urlpath);

		if (buf_error(url)) {
			free(form_buf);
			ret = buf_free(url);
			break;
		}
		if (!store_cookie_if_valid(vpninfo)) {
			buf_free(url);
			free(form_buf);
			ret = 0;
			break;
		}
		doc = htmlReadMemory(form_buf, ret, url->data, NULL,
				     HTML_PARSE_RECOVER | HTML_PARSE_NOERROR | HTML_PARSE_NOWARNING | HTML_PARSE_NONET);
		buf_free(url);
		free(form_buf);
		if (!doc) {
			vpn_progress(vpninfo, PRG_ERR, _("Failed to parse HTML document\n"));
			ret = -EINVAL;
			break;
		}

		buf_truncate(resp_buf);

		node = find_form_node(doc);
		if (!node) {
			vpn_progress(vpninfo, PRG_ERR, _("Failed to find or parse web form in login page\n"));
			ret = -EINVAL;
			break;
		}
		free(form_id);
		form_id = (char *)xmlGetProp(node, (unsigned char *)"name");
		if (!form_id) {
			vpn_progress(vpninfo, PRG_ERR, _("Encountered form with no ID\n"));
			goto dump_form;
		} else if (!strcmp(form_id, "Login")) {
			form = parse_form_node(vpninfo, node, "loginButton", NULL);

			if (!form) {
				ret = -EINVAL;
				break;
			}
		} else {
			vpn_progress(vpninfo, PRG_ERR, _("Unknown form ID '%s'\n"), form_id);
		dump_form:
			vpn_progress(vpninfo, PRG_ERR, _("Dumping unknown HTML form:\n"));
			htmlNodeDumpFileFormat(stderr, node->doc, node, NULL, 1);
			ret = -EINVAL;
			break;
		}

		do {
			ret = process_auth_form(vpninfo, form);
		} while (ret == OC_FORM_RESULT_NEWGROUP);
		if (ret)
			goto out;

		append_form_opts(vpninfo, form, resp_buf);
		ret = buf_error(resp_buf);
		if (ret)
			break;

		vpninfo->redirect_url = form->action;
		form->action = NULL;
		free_auth_form(form);
		form = NULL;
		handle_redirect(vpninfo);
	}
out:
	if (doc)
		xmlFreeDoc(doc);
	free(form_id);
	if (form)
		free_auth_form(form);
	buf_free(resp_buf);
	free(vpninfo->urlpath);
	vpninfo->urlpath = NULL;
	free(vpninfo->proto_data.nx.message);
	vpninfo->proto_data.nx.message = NULL;
	return ret;
}

void nx_common_headers(struct openconnect_info *vpninfo, struct oc_text_buf *buf)
{
	http_common_headers(vpninfo, buf);
	/*
	 * Apparently X-NE-SESSIONPROMPT: true seems to be needed in some rare (?)
	 * situations, where the tunnel will come up but no packets are
	 * transferred. See:
	 * https://github.com/abrasive/nxBender/commit/454dedc6c72fc62eedb7be18e62c6b7ee5f82bb3
	 *
	 * Of all the clients tested, ONLY NetExtender for Windows sends this header...
	 */
	buf_append(buf, "X-NE-SESSIONPROMPT: true\r\n");
}

/*
 * Trim any trailing blanks from key and
 * detect HTML in a roundabout way
 * by validating the key for acceptable characters
 */
static int validate_and_trim_key(char const **key, int *key_len)
{
	char const *k = *key;
	int i;
	while (isblank(k[*key_len - 1]))
		*key_len -= 1;

	for (i = 0; i < *key_len; i++) {
		if (!isalnum(k[i]) && k[i] != '.' && k[i] != '_') {
			return -EINVAL;
		}
	}
	return 0;
}

/*
 * first remove blanks in front,
 * then remove optional trailing semicolon and enclosing quotes
 */
static void trim_value(char const **value, int *value_len)
{
	while (isblank(**value))
		(*value)++;

	if (*(*value + *value_len - 1) == ';') {
		*value_len -= 1;
	}

	if (**value == '"' && *(*value + *value_len - 1) == '"') {
		(*value)++;
		*value_len -= 2;
	}
}

/*
 * allocates cfg_key and cfg_value,
 * leaves line intact so it can be printed in case of failure
 */
static int parse_connection_info_line(struct openconnect_info *vpninfo, char const *line, int const line_len,
				      char **cfg_key, char **cfg_value)
{
	/*
	<html><head><title>SonicWALL - Virtual Office</title><meta http-equiv='pragma' content='no-cache'><meta http-equiv='cache-control' content='no-cache'><meta http-equiv='cache-control' content='must-revalidate'><meta http-equiv='Content-Type' content='text/html;charset=UTF-8'><link href='/styleblueblackgrey.css' rel=stylesheet type='text/css'><script>function neLauncherInit(){
	NELaunchX1.userName = "someUsername";
	NELaunchX1.domainName = "LocalDomain";
	SessionId = QkMO6MFoXUdjMiCNLyakRw==;
	Route = 1.2.3.0/255.255.255.0
	Route = 4.5.6.0/255.255.255.0
	Ipv6Route = dead:beef:f00d:20::/64
	Ipv6Route = dead:beef:f00d:20::/64
	dns1 = 1.2.3.4
	dns2 = 4.5.6.7
	ipv6Support = yes
	GlobalIPv6Addr = dead:beef:f00d:1::1234
	dnsSuffix = example.com
	dnsSuffixes =example.com
	pppFrameEncoded = 0;
	PppPref = async
	TunnelAllMode = 0;
	ExitAfterDisconnect = 0;
	UninstallAfterExit = 0;
	NoProfileCreate = 0;
	AllowSavePassword = 0;
	AllowSaveUser = 1;
	AllowSavePasswordInKeychain = 0
	AllowSavePasswordInKeystore = 0
	ClientIPLower = "1.2.3.123";
	ClientIPHigh = "1.2.3.234";
	}</script></head></html>
	 */
	char const *key = NULL, *value = NULL;
	int key_len, value_len;
	char *equal_sign;
	*cfg_key = NULL;
	*cfg_value = NULL;
	/*
	 * The response is HTML and pretty inconsistent.
	 * Try to parse every line on a best-effort basis.
	 * - actual data is enclosed in a script-tag on some servers, on others they are not
	 * - keys are in one of the following forms delimited by newlines:
	 *    - Key = Value
	 *    - Key =Value
	 *    - Key = Value;
	 *    - Key = "Value"
	 *    - Key = "Value";
	 * - One server might use any of the above in the same response
	 *   (with/without quotes, with/without trailing semicolon,
	 *    with/without space around equals-sign)
	 */

	equal_sign = strchr(line, '=');
	if (!equal_sign)
		return -EINVAL;

	key = line;
	key_len = equal_sign - key;
	if (validate_and_trim_key(&key, &key_len))
		return -EINVAL;

	value = equal_sign + 1;
	value_len = line_len - (value - line);
	trim_value(&value, &value_len);

	*cfg_value = strndup(value, value_len);
	*cfg_key = strndup(key, key_len);
	if (!*cfg_key || !*cfg_value) {
		free(*cfg_key);
		free(*cfg_value);
		return -ENOMEM;
	}
	return 0;
}

static struct oc_split_include *add_split_include(struct oc_ip_info *new_ip_info,
						  char const *route)
{
	struct oc_split_include *include = malloc(sizeof(*include));
	if (!include)
		return NULL;

	include->route = route;
	include->next = new_ip_info->split_includes;
	new_ip_info->split_includes = include;
	return include;
}

/*
 * Takes ownership of key and value
 * We behave like CSTP — create a linked list in vpninfo->cstp_options
 * with the strings containing the information we got from the server,
 * and oc_ip_info contains const copies of those pointers.
 * Takes care of freeing if key is not added to vpninfo->cstp_options.
 */
static int populate_vpninfo(struct openconnect_info *vpninfo, struct oc_vpn_option **new_opts,
			    struct oc_ip_info *new_ip_info, char *key, char *value)
{
	if (strcmp(key, "Route") == 0 || strcmp(key, "Ipv6Route") == 0) {
		add_split_include(new_ip_info, add_option_steal(new_opts, key, &value));
	} else if (strcmp(key, "dns1") == 0) {
		new_ip_info->dns[0] = add_option_steal(new_opts, key, &value);
	} else if (strcmp(key, "dns2") == 0) {
		new_ip_info->dns[1] = add_option_steal(new_opts, key, &value);
	} else if (strcmp(key, "GlobalIPv6Addr") == 0) {
		new_ip_info->addr6 = add_option_steal(new_opts, key, &value);
	} else if (strcmp(key, "dnsSuffix") == 0) {
		if (new_ip_info->domain) {
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Not overwriting DNS domains with 'dnsSuffix', "
				       "because value from dnsSuffixes take precedence"));
			free(key);
			free(value);
			return 0;
		}
		new_ip_info->domain = add_option_steal(new_opts, key, &value);
	} else if (strcmp(key, "dnsSuffixes") == 0) {
		new_ip_info->domain = add_option_steal(new_opts, key, &value);
	} else {
		/* going to throw away key and value for the following keys */
		if (strcmp(key, "NX_TUNNEL_PROTO_VER") == 0) {
			if (strcmp(value, "2.0") != 0)
				vpn_progress(vpninfo, PRG_INFO,
					     _("Unknown NX tunnel protocol version '%s'.\n"
					       "Please report this to <openconnect-devel@lists.infradead.org>.\n"),
					     value);

		} else if (strcmp(key, "TunnelAllMode") == 0) {
			if (strcmp(value, "1") == 0) {
				add_split_include(new_ip_info, ipv4_default_route);
				if (new_ip_info->addr6) {
					add_split_include(new_ip_info, ipv6_default_route);
				}
			}
		} else if (strcmp(key, "SessionId") == 0) {
			/* separate in order to not print out secrets in message below */
		} else if (strcmp(key, "NELaunchX1.userName") == 0 ||
			   strcmp(key, "NELaunchX1.domainName") == 0 ||
			   strcmp(key, "ipv6Support") == 0 ||
			   strcmp(key, "pppFrameEncoded") == 0 ||
			   strcmp(key, "PppPref") == 0 ||
			   strcmp(key, "ExitAfterDisconnect") == 0 ||
			   strcmp(key, "UninstallAfterExit") == 0 ||
			   strcmp(key, "NoProfileCreate") == 0 ||
			   strcmp(key, "AllowSavePassword") == 0 ||
			   strcmp(key, "AllowSaveUser") == 0 ||
			   strcmp(key, "AllowSavePasswordInKeychain") == 0 ||
			   strcmp(key, "AllowSavePasswordInKeystore") == 0 ||
			   strcmp(key, "ClientIPLower") == 0 ||
			   strcmp(key, "ClientIPHigh") == 0) {
			vpn_progress(vpninfo, PRG_TRACE, _("Ignoring known config key/value-pair: %s: %s\n"), key,
				     value);
		} else {
			vpn_progress(vpninfo, PRG_DEBUG, _("Encountered unknown config key/value-pair: %s: %s\n"), key,
				     value);
		}
		free(key);
		free(value);
	}
	return 0;
}

static int nx_get_connection_info(struct openconnect_info *vpninfo)
{
	int ret = 0;
	char *result_buf = NULL;
	char *line, *line_break;
	int line_len;
	char *key, *value;
	char url[70];
	char const *support_ipv6 = (!vpninfo->disable_ipv6) ? "yes" : "no";
	struct oc_vpn_option *new_opts = NULL;
	struct oc_ip_info new_ip_info = {};

	snprintf(url, sizeof(url), "cgi-bin/sslvpnclient?launchplatform=mac&neProto=3&supportipv6=%s", support_ipv6);
	if (!vpninfo->cookies && vpninfo->cookie)
		http_add_cookie(vpninfo, "swap", vpninfo->cookie, 1);
	vpninfo->urlpath = url;
	ret = do_https_request(vpninfo, "GET", NULL, NULL, &result_buf, NULL, 0);
	vpninfo->urlpath = NULL;
	if (ret < 0)
		goto out;

	if (!strstr(result_buf, "SessionId")) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Did not get the expected response to the NX connection info request\n"
			       "Has the session expired?\n"));
		ret = -EINVAL;
		goto out;
	}
	line = result_buf;
	while (line) {
		line_break = strchr(line, '\n');
		if (line_break)
			*line_break = '\0';

		line_len = (line_break) ? line_break - line : strlen(line);
		ret = parse_connection_info_line(vpninfo, line, line_len, &key, &value);
		if (ret) {
			vpn_progress(vpninfo, PRG_DEBUG, _("Could not parse NX connection info line, ignoring: %s\n"),
				     line);
			ret = 0;
		} else {
			ret = populate_vpninfo(vpninfo, &new_opts, &new_ip_info,
					       key, value);
			if (ret)
				goto out;
		}
		line = line_break ? (line_break + 1) : NULL;
	}
	ret = install_vpn_opts(vpninfo, new_opts, &new_ip_info, 1);
out:
	if (ret) {
		free_optlist(new_opts);
                free_split_routes(&new_ip_info);
	}
	free(result_buf);
	return ret;
}

/* Translate platform names (derived from AnyConnect) into the values
 * known to be emitted by SonicWall NX clients for the X-NX-Client-Platform header
 */
static const char *nx_client_platform(struct openconnect_info *vpninfo)
{
	if (!strcmp(vpninfo->platname, "linux-64") || !strcmp(vpninfo->platname, "linux"))
		return "Linux";
	else if (!strcmp(vpninfo->platname, "android"))
		return "Android";
	else if (!strcmp(vpninfo->platname, "apple-ios"))
		return "iOS";
	else if (!strcmp(vpninfo->platname, "mac-intel"))
		return "MacOS";
	else
		return "Windows";
}

int nx_connect(struct openconnect_info *vpninfo)
{
	int ret = -EINVAL;
	struct oc_text_buf *reqbuf = NULL;
	char *auth_token = NULL;
	int auth_token_len = -1;
	int ipv4 = 1;

	if (!vpninfo->cookie) {
		vpn_progress(vpninfo, PRG_ERR, _("Malformed cookie or no cookie given\n"));
		return -EINVAL;
	}

	/* XX: Do we need to do this every time? Can't we skip it if this isn't
	 * the first connection? E.g. if vpninfo->ppp already exists? */
	ret = nx_get_connection_info(vpninfo);
	if (ret) {
		vpn_progress(vpninfo, PRG_ERR, _("Failed getting NX connection information\n"));
		return -EINVAL;
	}
	auth_token = openconnect_base64_decode(&auth_token_len, vpninfo->cookie);
	if (!auth_token) {
		ret = auth_token_len;
		goto out;
	}
	// TODO: get ECP (trojan) info from /cgi-bin/sslvpnclient?epcversionquery=nxx
	ret = openconnect_open_https(vpninfo);
	if (ret)
		goto out;

	reqbuf = buf_alloc();
	if (!reqbuf) {
		ret = -ENOMEM;
		goto out;
	}
	buf_append(reqbuf, "CONNECT localhost:0 HTTP/1.0\r\n");
	buf_append(reqbuf, "X-SSLVPN-PROTOCOL: 2.0\r\n");
	buf_append(reqbuf, "X-SSLVPN-SERVICE: NETEXTENDER\r\n");
	buf_append(reqbuf, "Connection-Medium: MacOS\r\n");
	buf_append(reqbuf, "Frame-Encode: off\r\n");
	buf_append(reqbuf, "X-NE-PROTOCOL: 2.0\r\n");
	buf_append(reqbuf, "Proxy-Authorization: %.*s\r\n", auth_token_len, auth_token);
	buf_append(reqbuf, "X-NX-Client-Platform: %s\r\n", nx_client_platform(vpninfo));
	buf_append(reqbuf, "User-Agent: %s\r\n", vpninfo->useragent);
	buf_append(reqbuf, "\r\n");
	if ((ret = buf_error(reqbuf) != 0)) {
		vpn_progress(vpninfo, PRG_ERR, _("Error creating HTTPS CONNECT request\n"));
		goto out;
	}
	if (vpninfo->dump_http_traffic)
		dump_buf(vpninfo, '>', reqbuf->data);
	vpninfo->ssl_write(vpninfo, reqbuf->data, reqbuf->pos);

	ret = openconnect_ppp_new(vpninfo, PPP_ENCAP_NX_HDLC, ipv4, vpninfo->ip_info.addr6 != NULL);

out:
	if (ret < 0)
		openconnect_close_https(vpninfo, 0);
	else {
		ppp_start_tcp_mainloop(vpninfo);
		monitor_fd_new(vpninfo, ssl);
		monitor_read_fd(vpninfo, ssl);
		monitor_except_fd(vpninfo, ssl);
	}

	buf_free(reqbuf);
	free(auth_token);
	return ret;
}

int nx_bye(struct openconnect_info *vpninfo, const char *reason)
{
	int ret = 0;
	char *resp_buf = NULL;
	struct oc_text_buf *request_body = NULL;
	/* close tunnel */
	openconnect_close_https(vpninfo, 0);

	request_body = buf_alloc();
	if (!request_body) {
		ret = buf_error(request_body);
		goto out;
	}
	append_opt(request_body, "userLogout", "1");
	vpninfo->urlpath = strdup("cgi-bin/userLogout");
	ret = do_https_request(vpninfo, "POST", "application/x-www-form-urlencoded", request_body, &resp_buf, NULL, 0);
	free(vpninfo->urlpath);
	vpninfo->urlpath = NULL;
	if (ret < 0)
		vpn_progress(vpninfo, PRG_ERR, _("Logout failed.\n"));
	else {
		ret = 0;
		vpn_progress(vpninfo, PRG_INFO, _("Logout successful.\n"));
	}

out:
	free(resp_buf);
	buf_free(request_body);
	return ret;
}
