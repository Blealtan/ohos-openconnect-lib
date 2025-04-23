/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2016-2018 Daniel Lenski
 *
 * Author: Dan Lenski <dlenski@gmail.com>
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

#include "openconnect-internal.h"

#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef _WIN32
#include <pwd.h>
#include <sys/inotify.h>
#endif

#define MAX_EVENTS 2
#define LEN_NAME 32
#define EVENT_SIZE  ( sizeof (struct inotify_event) ) /*size of one event*/
#define BUF_LEN     ( MAX_EVENTS * ( EVENT_SIZE + LEN_NAME ))

#define GP_DATA_FILE "globalprotect.dat"

struct login_context {
	char *username;				/* Username that has already succeeded in some form */
	char *alt_secret;			/* Alternative secret (DO NOT FREE) */
	char *portal_userauthcookie;		/* portal-userauthcookie (from global-protect/getconfig.esp) */
	char *portal_prelogonuserauthcookie;	/* portal-prelogonuserauthcookie (from global-protect/getconfig.esp) */
	char *region;				/* Region (typically 2 characters, e.g. DE, US) */
	struct oc_auth_form *form;
	int cas_auth;				/* Flag indicating whether cas auth is to be used */
	int reconnect;
};

static char *my_user = NULL;

void gpst_common_headers(struct openconnect_info *vpninfo,
			 struct oc_text_buf *buf)
{
	char *orig_ua = vpninfo->useragent;

	/* XX: more recent servers don't appear to require this specific UA value,
	 * but we don't have any good way to detect them.
	 */
	vpninfo->useragent = (char *)"PAN GlobalProtect";
	http_common_headers(vpninfo, buf);
	vpninfo->useragent = orig_ua;
}

/* Translate platform names (derived from AnyConnect) into the values
 * known to be emitted by GlobalProtect clients.
 */
const char *gpst_os_name(struct openconnect_info *vpninfo)
{
	if (!strcmp(vpninfo->platname, "mac-intel"))
		return "Mac";
	else if (!strcmp(vpninfo->platname, "apple-ios"))
		return "iOS";
	else if (!strcmp(vpninfo->platname, "linux-64") || !strcmp(vpninfo->platname, "linux"))
		return "Linux";
	else if (!strcmp(vpninfo->platname, "android"))
		return "Android";
	else
		return "Windows";
}

static struct oc_text_buf *get_user_cache_dir(void)
{
	struct oc_text_buf *cache_dir = buf_alloc();
#ifndef _WIN32
	struct passwd *pw = getpwuid(getuid());
	char *home = strdup(pw->pw_dir);
#else
	/* TODO: Add WIN32 implementation */
	char *home = strdup("");
#endif

	/* Ensure that the openconnect cache dir exists */
	buf_append(cache_dir, "%s/.cache/openconnect/", home);
	free(home);

#ifndef _WIN32
	mkdir(cache_dir->data, 0700);
#else
	CreateDirectory(cache_dir->data, NULL);
#endif

	return cache_dir;
}

/* Parse pre-login response ({POST,GET} /{global-protect,ssl-vpn}/pre-login.esp)
 *
 * Extracts the relevant arguments from the XML (username-label, password-label)
 * and uses them to build an auth form, which always has 2-3 fields:
 *
 *   1) username (hidden in challenge forms, since it's simply repeated)
 *   2) one secret value:
 *       - normal account password
 *       - "challenge" (2FA) password
 *       - cookie from external authentication flow ("alternative secret" INSTEAD OF password)
 *   3) inputStr for challenge form (shoehorned into form->action)
 *
 */
static int parse_prelogin_xml(struct openconnect_info *vpninfo, xmlNode *xml_node, void *cb_data)
{
	struct login_context *ctx = cb_data;
	struct oc_auth_form *form = NULL;
	struct oc_form_opt *opt, *opt2;
	char *prompt = NULL, *username_label = NULL, *password_label = NULL;
	char *s = NULL, *saml_method = NULL, *saml_path = NULL;
	int result = -EINVAL;
	int default_browser = 0;
	int cas_auth = 0;

	if (!xmlnode_is_named(xml_node, "prelogin-response"))
		goto out;

	for (xml_node = xml_node->children; xml_node; xml_node = xml_node->next) {
		if (xmlnode_is_named(xml_node, "saml-default-browser"))
			default_browser = xmlnode_bool_or_int_value(xml_node);
		if (xmlnode_is_named(xml_node, "cas-auth"))
			cas_auth = xmlnode_bool_or_int_value(xml_node);

		xmlnode_get_val(xml_node, "saml-request", &s);
		xmlnode_get_val(xml_node, "saml-auth-method", &saml_method);
		xmlnode_get_trimmed_val(xml_node, "authentication-message", &prompt);
		xmlnode_get_trimmed_val(xml_node, "username-label", &username_label);
		xmlnode_get_trimmed_val(xml_node, "password-label", &password_label);
		xmlnode_get_trimmed_val(xml_node, "region", &ctx->region);
		/* XX: should we save the certificate username from <ccusername/> ? */
	}

	if (default_browser != 0) {
		vpn_progress(vpninfo, PRG_INFO, "Using default browser\n");
		ctx->cas_auth = cas_auth;
	}

	if (saml_method && s) {
		/* Allow the legacy workflow (no GUI setting up open_webview) to keep working */
		if (!vpninfo->open_webview && ctx->portal_userauthcookie)
			vpn_progress(vpninfo, PRG_DEBUG, _("SAML authentication required; using portal-userauthcookie to continue SAML.\n"));
		else if (!vpninfo->open_webview && ctx->portal_prelogonuserauthcookie)
			vpn_progress(vpninfo, PRG_DEBUG, _("SAML authentication required; using portal-prelogonuserauthcookie to continue SAML.\n"));
		else if (!vpninfo->open_webview && ctx->alt_secret)
			vpn_progress(vpninfo, PRG_DEBUG, _("Destination form field %s was specified; assuming SAML %s authentication is complete.\n"),
			             ctx->alt_secret, saml_method);
		else {
			if (!strcmp(saml_method, "REDIRECT")) {
				int len;
				saml_path = openconnect_base64_decode(&len, s);
				if (len < 0) {
					vpn_progress(vpninfo, PRG_ERR, "Could not decode SAML request as base64: %s\n", s);
					free(s);
					goto out;
				}
				free(s);
				realloc_inplace(saml_path, len+1);
				if (!saml_path)
					goto nomem;
				saml_path[len] = '\0';
				free(vpninfo->sso_login);
				vpninfo->sso_login = strdup(saml_path);
				prompt = strdup("SAML REDIRECT authentication in progress");
				if (!vpninfo->sso_login || !prompt)
					goto nomem;
			} else if (!strcmp(saml_method, "POST")) {
				const char *prefix = "data:text/html;base64,";
				saml_path = s;
				realloc_inplace(saml_path, strlen(saml_path)+strlen(prefix)+1);
				if (!saml_path)
					goto nomem;
				memmove(saml_path + strlen(prefix), saml_path, strlen(saml_path) + 1);
				memcpy(saml_path, prefix, strlen(prefix));
				free(vpninfo->sso_login);
				vpninfo->sso_login = strdup(saml_path);
				prompt = strdup("SAML REDIRECT authentication in progress");
				if (!vpninfo->sso_login || !prompt)
					goto nomem;
			} else {
				vpn_progress(vpninfo, PRG_ERR, "Unknown SAML method %s\n", saml_method);
				goto out;
			}

			vpn_progress(vpninfo, PRG_INFO,
					_("SAML %s authentication is required via %s\n"),
					saml_method, saml_path);

			/* Legacy flow (when not called by n-m-oc) */
			if (!vpninfo->open_webview) {
				vpn_progress(vpninfo,
					PRG_ERR, _("When SAML authentication is complete, specify destination form field by appending :field_name to login URL.\n"));
				goto out;
			}
		}
	}

	/* Replace old form */
	form = ctx->form = calloc(1, sizeof(*form));
	if (!form) {
	nomem:
		free_auth_form(form);
		result = -ENOMEM;
		goto out;
	}
	form->message = prompt ? : strdup(_("Please enter your username and password"));
	prompt = NULL;
	form->auth_id = strdup("_login");

	/* First field (username) */
	opt = form->opts = calloc(1, sizeof(*opt));
	if (!opt)
		goto nomem;
	opt->name = strdup("user");
	if (!opt->name)
		goto nomem;
	if (asprintf(&opt->label, "%s: ", username_label ? : _("Username")) <= 0)
		goto nomem;
	if (!ctx->username)
		opt->type = saml_path ? OC_FORM_OPT_SSO_USER : OC_FORM_OPT_TEXT;
	else {
		opt->type = OC_FORM_OPT_HIDDEN;
		opt->_value = ctx->username;
		ctx->username = NULL;
	}

	/* Second field (secret) */
	opt2 = opt->next = calloc(1, sizeof(*opt));
	if (!opt2)
		goto nomem;
	opt2->name = strdup(ctx->alt_secret ? : "passwd");
	if (!opt2->name)
		goto nomem;
	if (asprintf(&opt2->label, "%s: ", ctx->alt_secret ? : password_label ? : _("Password")) <= 0)
		goto nomem;

	/* XX: Some VPNs use a password in the first form, followed by a
	 * a token in the second ("challenge") form. Others use only a
	 * token. How can we distinguish these?
	 *
	 * Currently using the heuristic that a non-default label for the
	 * password in the first form means we should treat the first
	 * form's password as a token field.
	 */
	if (saml_path)
		opt2->type = OC_FORM_OPT_SSO_TOKEN;
	else if (!can_gen_tokencode(vpninfo, form, opt2) && !ctx->alt_secret
	         && password_label && strcmp(password_label, "Password"))
		opt2->type = OC_FORM_OPT_TOKEN;
	else
		opt2->type = OC_FORM_OPT_PASSWORD;

	result = 0;
	vpn_progress(vpninfo, PRG_TRACE, "Prelogin form %s: \"%s\" %s(%s)=%s, \"%s\" %s(%s)\n",
	             form->auth_id,
	             opt->label, opt->name, opt->type == OC_FORM_OPT_SSO_USER ? "SSO" : opt->type == OC_FORM_OPT_TEXT ? "TEXT" : "HIDDEN", opt->_value,
	             opt2->label, opt2->name, opt2->type == OC_FORM_OPT_SSO_TOKEN ? "SSO" : opt2->type == OC_FORM_OPT_PASSWORD ? "PASSWORD" : "TOKEN");

out:
	free(prompt);
	free(username_label);
	free(password_label);
	free(saml_method);
	free(saml_path);
	return result;
}

/* Callback function to create a new form from a challenge
 *
 */
static int challenge_cb(struct openconnect_info *vpninfo, char *prompt, char *inputStr, void *cb_data)
{
	struct login_context *ctx = cb_data;
	struct oc_auth_form *form = ctx->form;
	struct oc_form_opt *opt = form->opts, *opt2 = form->opts->next;

	/* Replace prompt, inputStr, and password prompt;
	 * clear password field, and make user field hidden.
	 */
	free(form->message);
	free(form->auth_id);
	free(form->action);
	free(opt2->label);
	free(opt2->_value);
	opt2->_value = NULL;
	opt->type = OC_FORM_OPT_HIDDEN;

	/* XX: Some VPNs use a password in the first form, followed by a
	 * a token in the second ("challenge") form. Others use only a
	 * token. How can we distinguish these?
	 *
	 * Currently using the heuristic that if the password field in
	 * the preceding form wasn't treated as a token field, treat this
	 * as a token field.
        */
	if (!can_gen_tokencode(vpninfo, form, opt2) && opt2->type == OC_FORM_OPT_PASSWORD)
		opt2->type = OC_FORM_OPT_TOKEN;
	else
		opt2->type = OC_FORM_OPT_PASSWORD;

	if (    !(form->message = strdup(prompt))
		 || !(form->action = strdup(inputStr))
		 || !(form->auth_id = strdup("_challenge"))
		 || !(opt2->label = strdup(_("Challenge: "))) )
		return -ENOMEM;

	vpn_progress(vpninfo, PRG_TRACE, "Challenge form %s: \"%s\" %s(%s)=%s, \"%s\" %s(%s), inputStr=%s\n",
	             form->auth_id,
	             opt->label, opt->name, opt->type == OC_FORM_OPT_TEXT ? "TEXT" : "HIDDEN", opt->_value,
	             opt2->label, opt2->name, opt2->type == OC_FORM_OPT_PASSWORD ? "PASSWORD" : "TOKEN",
	             inputStr);

	return -EAGAIN;
}

/* Parse gateway login response (POST /ssl-vpn/login.esp)
 *
 * Extracts the relevant arguments from the XML (<jnlp><application-desc><argument>...</argument></application-desc></jnlp>)
 * and uses them to build a query string fragment which is usable for subsequent requests.
 * This query string fragment is saved as vpninfo->cookie.
 *
 */
struct gp_login_arg {
	const char *opt;
	unsigned save:1;
	unsigned show:1;
	unsigned warn_missing:1;
	unsigned err_missing:1;
	unsigned unknown:1;
	const char *check;
};
static const struct gp_login_arg gp_login_args[] = {
	{ .unknown=1 },                                 /* seemingly always empty */
	{ .opt="authcookie", .save=1, .err_missing=1 },
	{ .opt="persistent-cookie", .warn_missing=1 },  /* 40 hex digits; persists across sessions */
	{ .opt="portal", .save=1, .warn_missing=1 },
	{ .opt="user", .save=1, .err_missing=1 },
	{ .opt="authentication-source", .show=1 },      /* LDAP-auth, AUTH-RADIUS_RSA_OTP, etc. */
	{ .opt="configuration", .warn_missing=1 },      /* usually vsys1 (sometimes vsys2, etc.) */
	{ .opt="domain", .save=1, .warn_missing=1 },
	{ .unknown=1 },                                 /* 4 arguments, seemingly always empty */
	{ .unknown=1 },
	{ .unknown=1 },
	{ .unknown=1 },
	{ .opt="connection-type", .err_missing=1, .check="tunnel" },
	{ .opt="password-expiration-days", .show=1 },   /* days until password expires, if not -1 */
	{ .opt="clientVer", .err_missing=1, .check="4100" },
	{ .opt="preferred-ip", .save=1 },
	{ .opt="portal-userauthcookie", .show=1},
	{ .opt="portal-prelogonuserauthcookie", .show=1},
	{ .opt="preferred-ipv6", .save=1 },
	{ .opt="usually-equals-4", .show=1 },           /* newer servers send "4" here, meaning unknown */
	{ .opt="usually-equals-unknown", .show=1 },     /* newer servers send "unknown" here */
};
static const int gp_login_nargs = ARRAY_SIZE(gp_login_args);

static int parse_login_xml(struct openconnect_info *vpninfo, xmlNode *xml_node, void *cb_data)
{
	struct oc_text_buf *cookie = buf_alloc();
	char *value = NULL;
	const struct gp_login_arg *arg;
	int argn, unknown_args = 0, fatal_args = 0;

	if (!xmlnode_is_named(xml_node, "jnlp"))
		goto err_out;

	xml_node = xml_node->children;
	while (xml_node && xml_node->type != XML_ELEMENT_NODE)
		xml_node = xml_node->next;

	if (!xml_node || !xmlnode_is_named(xml_node, "application-desc"))
		goto err_out;

	xml_node = xml_node->children;
	/* XXX: Loop as long as there are EITHER more known arguments OR more XML tags,
	 * so that we catch both more-than-expected and fewer-than-expected arguments. */
	for (argn = 0; argn < gp_login_nargs || xml_node; argn++) {
		while (xml_node && xml_node->type != XML_ELEMENT_NODE)
			xml_node = xml_node->next;

		/* XX: argument 0 is unknown so we reuse this for extra arguments */
		arg = &gp_login_args[(argn < gp_login_nargs) ? argn : 0];

		if (!xml_node)
			value = NULL;
		else if (!xmlnode_get_val(xml_node, "argument", &value)) {
			if (value && (!value[0] || !strcmp(value, "(null)") || !strcmp(value, "-1"))) {
				free(value);
				value = NULL;
			} else if (arg->save) {
				/* XX: Some of the fields returned here (e.g. portal-*cookie) should NOT be
				 * URL-decoded in order to be reused correctly, but the ones which get saved
				 * into "cookie" must be URL-decoded. They will be needed for the (stupidly
				 * redundant) logout parameters. In particular the domain value "%28empty_domain%29"
				 * appears frequently in the wild, and it needs to be decoded here for the logout
				 * request to succeed.
				 */
				urldecode_inplace(value);
			}
			xml_node = xml_node->next;
		} else
			goto err_out;

		if (arg->unknown && value) {
			unknown_args++;
			vpn_progress(vpninfo, PRG_ERR,
						 _("GlobalProtect login returned unexpected argument value arg[%d]=%s\n"),
						 argn, value);
		} else if (arg->check && (!value || strcmp(value, arg->check))) {
			unknown_args++;
			fatal_args += arg->err_missing;
			vpn_progress(vpninfo, PRG_ERR,
			             _("GlobalProtect login returned %s=%s (expected %s)\n"),
			             arg->opt, value, arg->check);
		} else if ((arg->err_missing || arg->warn_missing) && !value) {
			unknown_args++;
			fatal_args += arg->err_missing;
			vpn_progress(vpninfo, PRG_ERR,
			             _("GlobalProtect login returned empty or missing %s\n"),
			             arg->opt);
		} else if (value && arg->show) {
			vpn_progress(vpninfo, PRG_INFO,
			             _("GlobalProtect login returned %s=%s\n"),
			             arg->opt, value);
		}

		if (value && arg->save)
			append_opt(cookie, arg->opt, value);

		free(value);
		value = NULL;
	}
	append_opt(cookie, "computer", vpninfo->localname);

	if (unknown_args)
		vpn_progress(vpninfo, PRG_ERR,
					 _("Please report %d unexpected values above (of which %d fatal) to <%s>\n"),
					 unknown_args, fatal_args,
					 "openconnect-devel@lists.infradead.org");
	if (fatal_args) {
		buf_free(cookie);
		return -EPERM;
	}

	if (!buf_error(cookie)) {
		vpninfo->cookie = cookie->data;
		cookie->data = NULL;
	}
	return buf_free(cookie);

err_out:
	free(value);
	buf_free(cookie);
	return -EINVAL;
}

static int compare_choices(const void *a, const void *b)
{
	const struct oc_choice *const *_a = a, *c1 = *_a;
	const struct oc_choice *const *_b = b, *c2 = *_b;
	return (c1->priority - c2->priority);
}

static void store_cookie (const char *portal, const char *gateway, const char *user, const char *cookie)
{
	FILE *file;
	struct oc_text_buf *buf = buf_alloc();
	struct oc_text_buf *tmp_file = buf_alloc();
	struct oc_text_buf *oc_cache_dir = buf_alloc();

	oc_cache_dir = get_user_cache_dir ();
	buf_append(tmp_file, "%s/reconnect", oc_cache_dir->data);
	buf_free(oc_cache_dir);

	file = fopen(tmp_file->data, "w");
	buf_free(tmp_file);

	buf_append(buf, "%s;%s;%s;%s", portal, gateway, user, cookie);

	fwrite(buf->data, 1, buf->pos, file);
	fclose(file);

	buf_free(buf);
}

/* Parse portal login/config response (POST /ssl-vpn/getconfig.esp)
 *
 * Extracts the list of gateways from the XML, writes them to the XML config,
 * presents the user with a form to choose the gateway, and redirects
 * to that gateway.
 *
 */
static int parse_portal_xml(struct openconnect_info *vpninfo, xmlNode *xml_node, void *cb_data)
{
	struct login_context *ctx = cb_data;
	struct oc_auth_form *form;
	xmlNode *x, *x2, *x3, *gateways = NULL;
	struct oc_form_opt_select *opt;
	struct oc_text_buf *buf = NULL;
	int max_choices = 0, result;
	char *portal = NULL;
	char *hip_interval = NULL;

	form = calloc(1, sizeof(*form));
	if (!form)
		return -ENOMEM;

	form->message = strdup(_("Please select GlobalProtect gateway."));
	form->auth_id = strdup("_portal");

	opt = form->authgroup_opt = calloc(1, sizeof(*opt));
	if (!opt) {
		result = -ENOMEM;
		goto out;
	}
	opt->form.type = OC_FORM_OPT_SELECT;
	opt->form.name = strdup("gateway");
	opt->form.label = strdup(_("GATEWAY:"));
	form->opts = (void *)opt;

	/*
	 * The portal contains a ton of stuff, but basically none of it is
	 * useful to a VPN client that wishes to give control to the client
	 * user, as opposed to the VPN administrator.  The exception is
	 * the list of gateways in policy/gateways/external/list.
	 *
	 * There are other fields which are worthless in terms of end-user
	 * functionality, but are needed for compliance with the server's
	 * security policies:
	 * - Interval for HIP checks in policy/hip-collection/hip-report-interval
	 *   (save so that we can rerun HIP on the expected interval)
	 * - Software version (save so we can mindlessly parrot it back)
	 *
	 * Potentially also useful, but currently ignored:
	 * - welcome-page/page, help-page, and help-page-2 contents might in
	 *   principle be informative, but in practice they're either empty
	 *   or extremely verbose multi-page boilerplate in HTML format
	 * - hip-collection/default/category/member[] might be useful
	 *   to report to the user as a diagnostic, so that they know what
	 *   HIP report entries the server expects, if their HIP report
	 *   isn't expected. In practice, servers that actually check the HIP
	 *   report contents are so nitpicky that anything less than a
	 *   capture from an officially-supported client is unlikely to help.
	 * - root-ca/entry[]/cert is potentially useful because it contains
	 *   certs that we should allow as root-of-trust for the gateway
	 *   servers. This could prevent users from having to specify --cafile
	 *   or repeated --servercert in order to allow non-interactive
	 *   authentication to gateways whose certs aren't trusted by the
	 *   system but ARE trusted by the portal (see example at
         *   https://github.com/dlenski/openconnect/issues/128).
	 */
	if (xmlnode_is_named(xml_node, "policy")) {
		for (x = xml_node->children; x; x = x->next) {
			if (xmlnode_is_named(x, "gateways")) {
				for (x2 = x->children; x2; x2 = x2->next)
					if (xmlnode_is_named(x2, "external"))
						for (x3 = x2->children; x3; x3 = x3->next)
							if (xmlnode_is_named(x3, "list"))
								gateways = x3;
			} else if (xmlnode_is_named(x, "hip-collection")) {
				for (x2 = x->children; x2; x2 = x2->next) {
					if (!xmlnode_get_val(x2, "hip-report-interval", &hip_interval)) {
						int sec = atoi(hip_interval);
						if (vpninfo->trojan_interval)
							vpn_progress(vpninfo, PRG_INFO, _("Ignoring portal's HIP report interval (%d minutes), because interval is already set to %d minutes.\n"),
										 sec/60, vpninfo->trojan_interval/60);
						else {
							vpninfo->trojan_interval = sec - 60;
							vpn_progress(vpninfo, PRG_INFO, _("Portal set HIP report interval to %d minutes).\n"),
										 sec/60);
						}
					}
				}
			} else if (!xmlnode_get_trimmed_val(x, "version", &vpninfo->csd_ticket)) {
				/* We abuse csd_ticket to store the portal's software version. Parroting this back as
				 * the client software version (app-version) appears to be the best way to prevent the
				 * gateway server from rejecting the connection due to obsolete client software.
				 */
				vpn_progress(vpninfo, PRG_INFO, _("Portal reports GlobalProtect version %s; we will report the same client version.\n"),
					     vpninfo->csd_ticket);
			} else {
				xmlnode_get_val(x, "portal-name", &portal);
				if (!xmlnode_get_val(x, "portal-userauthcookie", &ctx->portal_userauthcookie)) {
					if (!*ctx->portal_userauthcookie || !strcmp(ctx->portal_userauthcookie, "empty")) {
						free(ctx->portal_userauthcookie);
						ctx->portal_userauthcookie = NULL;
					}
				}
				if (!xmlnode_get_val(x, "portal-prelogonuserauthcookie", &ctx->portal_prelogonuserauthcookie)) {
					if (!*ctx->portal_prelogonuserauthcookie || !strcmp(ctx->portal_prelogonuserauthcookie, "empty")) {
						free(ctx->portal_prelogonuserauthcookie);
						ctx->portal_prelogonuserauthcookie = NULL;
					}
				}
			}
		}
	}

	if (!gateways) {
no_gateways:
		vpn_progress(vpninfo, PRG_ERR,
					 _("GlobalProtect portal configuration lists no gateway servers.\n"));
		result = -EINVAL;
		goto out;
	}

	if (vpninfo->write_new_config) {
		buf = buf_alloc();
		buf_append(buf, "<GPPortal>\n  <ServerList>\n");
		buf_append(buf, "      <HostEntry><HostName>");
		buf_append_xmlescaped(buf, portal ? : _("unknown"));
		buf_append(buf, "</HostName><HostAddress>%s", vpninfo->hostname);
		if (vpninfo->port!=443)
			buf_append(buf, ":%d", vpninfo->port);
		buf_append(buf, "/global-protect</HostAddress></HostEntry>\n");
	}

	/* first, count the number of gateways */
	for (x = gateways->children; x; x = x->next)
		if (xmlnode_is_named(x, "entry"))
			max_choices++;

	opt->choices = calloc(max_choices, sizeof(opt->choices[0]));
	if (!opt->choices) {
		result = -ENOMEM;
		goto out;
	}

	/* Each entry looks like:
	 *   <entry name="host[:443]">
	 *     <description>Label</description>
	 *     <priority-rule>           <!-- This is optional -->
	 *       <entry name="US"><priority>1</priority></entry>
	 *       <entry name="DE"><priority>2</priority></entry>
	 *       <entry name="Any"><priority>3</priority></entry>
	 *     </priority-rule>
	 *   </entry>
	 */
	vpn_progress(vpninfo, PRG_INFO, _("%d gateway servers available:\n"), max_choices);
	for (x = gateways->children; x; x = x->next) {
		if (xmlnode_is_named(x, "entry")) {
			struct oc_choice *choice = calloc(1, sizeof(*choice));

			if (!choice) {
				result = -ENOMEM;
				goto out;
			}

			choice->priority = INT_MAX;
			xmlnode_get_prop(x, "name", &choice->name);
			for (x2 = x->children; x2; x2 = x2->next) {
				if (ctx->region && xmlnode_is_named(x2, "priority-rule")) {
					/* Extract priority for our region (also matching to 'Any'). */
					for (xmlNode *entry = x2->children; entry; entry = entry->next) {
						char *entry_name = NULL;
						if (xmlnode_is_named(entry, "entry") &&
						    !xmlnode_get_prop(entry, "name", &entry_name)) {
							if (!strcmp(ctx->region, entry_name) || !strcmp("Any", entry_name)) {
								for (xmlNode *x3 = entry->children; x3; x3 = x3->next) {
									if (xmlnode_is_named(x3, "priority")) {
										/* Use lowest if there are multiple matches (e.g. both exact and 'Any') */
										int p = xmlnode_bool_or_int_value(x3);
										if (p < choice->priority)
											choice->priority = p;
									}
								}
							}
						}
						free(entry_name);
					}
				} else
					xmlnode_get_val(x2, "description", &choice->label);
			}

			opt->choices[opt->nr_choices++] = choice;
			if (choice->priority != INT_MAX)
				vpn_progress(vpninfo, PRG_INFO, _("  %s (%s) [priority %d]\n"),
					     choice->label, choice->name, choice->priority);
			else
				vpn_progress(vpninfo, PRG_INFO, _("  %s (%s) [unprioritized]\n"),
					     choice->label, choice->name);
		}
	}
	if (!opt->nr_choices)
		goto no_gateways;

	qsort(opt->choices, opt->nr_choices, sizeof(*opt->choices), compare_choices);
	if (vpninfo->write_new_config) {
		for (int i = 0; i < opt->nr_choices; i++) {
			buf_append(buf, "      <HostEntry><HostName>");
			buf_append_xmlescaped(buf, opt->choices[i]->label);
			buf_append(buf, "</HostName><HostAddress>%s/ssl-vpn</HostAddress></HostEntry>\n",
					   opt->choices[i]->name);
		}
	}

	if (!vpninfo->authgroup && opt->nr_choices)
		vpninfo->authgroup = strdup(opt->choices[0]->name);

	if (vpninfo->write_new_config) {
		buf_append(buf, "  </ServerList>\n</GPPortal>\n");
		if ((result = buf_error(buf)))
			goto out;
		if ((result = vpninfo->write_new_config(vpninfo->cbdata, buf->data, buf->pos)))
			goto out;
	}

	/* process auth form to select gateway */
	result = process_auth_form(vpninfo, form);
	if (result == OC_FORM_RESULT_CANCELLED || result < 0)
		goto out;

	/* redirect to the gateway (no-op if it's the same host) */
	free(vpninfo->redirect_url);
	if (asprintf(&vpninfo->redirect_url, "https://%s", vpninfo->authgroup) == 0) {
		result = -ENOMEM;
		goto out;
	}
	result = handle_redirect(vpninfo);

out:
	buf_free(buf);
	free(portal);
	free(hip_interval);
	free_auth_form(form);
	return result;
}

/* Main login entry point
 *
 * portal: 0 for gateway login, 1 for portal login
 * alt_secret: "alternate secret" field (see new_auth_form)
 *
 */
static int gpst_login(struct openconnect_info *vpninfo, int portal, struct login_context *ctx)
{
	int result, blind_retry = 0;
	struct oc_text_buf *request_body = buf_alloc();
	char *xml_buf = NULL, *orig_path;

	if (ctx->reconnect)
		goto reconnect;

	/* Ask the user to fill in the auth form; repeat as necessary */
	for (;;) {
		int keep_urlpath = 0;
		if (vpninfo->urlpath) {
			/* XX: If the path ends with .esp (possibly followed by a query string), leave as-is */
			const char *esp = strstr(vpninfo->urlpath, ".esp");
			if (esp && (esp[4] == '\0' || esp[4] == '?'))
				keep_urlpath = 1;
		}
		if (!keep_urlpath) {
			orig_path = vpninfo->urlpath;
			if (asprintf(&vpninfo->urlpath, "%s/prelogin.esp?tmp=tmp&clientVer=4100&clientos=%s&default-browser=4&cas-support=yes",
				portal ? "global-protect" : "ssl-vpn", gpst_os_name(vpninfo)) < 0) {
				result = -ENOMEM;
				goto out;
			}
		}
		/* submit prelogin request to get form */
		buf_truncate(request_body);
		if (!vpninfo->no_external_auth)
			buf_append(request_body, "cas-support=yes");
		result = do_https_request(vpninfo, "POST", "application/x-www-form-urlencoded", request_body, &xml_buf, NULL, HTTP_REDIRECT);
		if (!keep_urlpath) {
			free(vpninfo->urlpath);
			vpninfo->urlpath = orig_path;
		}

		if (result >= 0)
			result = gpst_xml_or_error(vpninfo, xml_buf, parse_prelogin_xml, NULL, ctx);
		if (result)
			goto out;

got_form:
		/* process auth form */
		result = process_auth_form(vpninfo, ctx->form);
		if (result)
			goto out;

		/* Coming back from SAML we might have been redirected */
		if (vpninfo->redirect_url) {
			result = handle_redirect(vpninfo);
			free(vpninfo->redirect_url);
			vpninfo->redirect_url = NULL;
			if (result)
				goto out;
		}

replay_form:
		/* generate token code if specified */
		result = do_gen_tokencode(vpninfo, ctx->form);
		if (result) {
			vpn_progress(vpninfo, PRG_ERR, _("Failed to generate OTP tokencode; disabling token\n"));
			vpninfo->token_bypassed = 1;
			goto out;
		}

reconnect:
		/* submit gateway login (ssl-vpn/login.esp) or portal config (global-protect/getconfig.esp) request */
		buf_truncate(request_body);
		buf_append(request_body, "jnlpReady=jnlpReady&ok=Login&direct=yes&clientVer=4100&prot=https:&internal=no");
		append_opt(request_body, "ipv6-support", vpninfo->disable_ipv6 ? "no" : "yes");
		append_opt(request_body, "clientos", gpst_os_name(vpninfo));
		append_opt(request_body, "os-version", vpninfo->platname);
		append_opt(request_body, "server", vpninfo->hostname);
		append_opt(request_body, "computer", vpninfo->localname);
		if (ctx->username)
			append_opt(request_body, "user", ctx->username);
		if (portal == 1 && ctx->cas_auth && vpninfo->sso_token_cookie)
			append_opt(request_body, "token", vpninfo->sso_token_cookie);
		if (ctx->portal_userauthcookie)
			append_opt(request_body, "portal-userauthcookie", ctx->portal_userauthcookie);
		if (ctx->portal_prelogonuserauthcookie)
			append_opt(request_body, "portal-prelogonuserauthcookie", ctx->portal_prelogonuserauthcookie);

		if (vpninfo->ip_info.addr)
			append_opt(request_body, "preferred-ip", vpninfo->ip_info.addr);
		if (vpninfo->ip_info.addr6)
			append_opt(request_body, "preferred-ipv6", vpninfo->ip_info.addr);
		if (ctx->form) {
			if (ctx->form->action)
				append_opt(request_body, "inputStr", ctx->form->action);
			append_form_opts(vpninfo, ctx->form, request_body);
		}
		if ((result = buf_error(request_body)))
			goto out;

		orig_path = vpninfo->urlpath;
		vpninfo->urlpath = strdup(portal ? "global-protect/getconfig.esp" : "ssl-vpn/login.esp");
		result = do_https_request(vpninfo, "POST", "application/x-www-form-urlencoded", request_body, &xml_buf, NULL, HTTP_NO_FLAGS);
		free(vpninfo->urlpath);
		vpninfo->urlpath = orig_path;

		/* Result could be either a JavaScript challenge or XML */
		if (result >= 0)
			result = gpst_xml_or_error(vpninfo, xml_buf, portal ? parse_portal_xml : parse_login_xml,
									   challenge_cb, ctx);

		if (result != 0 && ctx->reconnect == 1)
			goto out;

		if (result == -EACCES) {
			/* Invalid username/password; reuse same form, but blank,
			 * unless we just did a blind retry.
			 */
			if (ctx->form)
				nuke_opt_values(ctx->form->opts);
			else
				blind_retry = 0;

			if (!blind_retry)
				goto got_form;
			else
				blind_retry = 0;
		} else {
			/* Save successful username */
			if (!ctx->username && ctx->form && ctx->form->opts->_value)
				ctx->username = strdup(ctx->form->opts->_value);
			if (result == -EAGAIN) {
				/* New form is already populated from the challenge */
				goto got_form;
			} else if (portal && result == 0) {
				/* Portal login succeeded; blindly retry same credentials on gateway if:
				 *      (a) we received a cookie that should allow automatic retry
				 *   OR (b) portal form was neither challenge auth nor alt-secret (SAML)
				 */
				portal = 0;
				if (ctx->portal_userauthcookie || ctx->portal_prelogonuserauthcookie ||
				    (ctx->form &&(strcmp(ctx->form->auth_id, "_challenge")) && !ctx->alt_secret)) {
					blind_retry = 1;
					goto replay_form;
				}
			} else
				break;
		}
	}

out:
	buf_free(request_body);
	free(xml_buf);
	return result;
}

static char** str_split(char* a_str, const char a_delim)
{
    char** result    = 0;
    size_t count     = 0;
    char* tmp        = a_str;
    char* last_comma = 0;
    char delim[2];
    delim[0] = a_delim;
    delim[1] = 0;

    /* Count how many elements will be extracted. */
    while (*tmp)
    {
        if (a_delim == *tmp)
        {
            count++;
            last_comma = tmp;
        }
        tmp++;
    }

    /* Add space for trailing token. */
    count += last_comma < (a_str + strlen(a_str) - 1);

    /* Add space for terminating null string so caller
       knows where the list of returned strings ends. */
    count++;

    result = malloc(sizeof(char*) * count);

    if (result)
    {
        size_t idx  = 0;
        char* token = strtok(a_str, delim);

        while (token)
        {
            /* assert(idx < count); */
            *(result + idx++) = strdup(token);
            token = strtok(0, delim);
        }
        /* assert(idx == count - 1); */
        *(result + idx) = 0;
    }

    return result;
}

static int try_reconnect (struct openconnect_info *vpninfo)
{
	struct login_context ctx = { .username=NULL, .alt_secret=NULL, .portal_userauthcookie=NULL, .portal_prelogonuserauthcookie=NULL, .form=NULL };
	FILE *fptr;
	char *data;
	int size;
	struct oc_text_buf *tmp_file = buf_alloc();
	struct oc_text_buf *oc_cache_dir = buf_alloc();
	int result;
	char *portal;
	char *gateway;
	char *user;
	char *cookie;
	char **entries;
        char *old_hostname;

	oc_cache_dir = get_user_cache_dir ();
	buf_append(tmp_file, "%s/reconnect", oc_cache_dir->data);
	buf_free(oc_cache_dir);

	/* Open callback data file */
	fptr = fopen(tmp_file->data, "r");
	if (!fptr) {
		vpn_progress(vpninfo, PRG_INFO, "Failed to open file %s\n", tmp_file->data);
		return -1;
	}

	/* Get file size */
	fseek(fptr, 0L, SEEK_END);
	size = ftell(fptr);
	fseek(fptr, 0L, SEEK_SET);

	/* Read data */
	data = malloc(size + 1);
	memset(data, 0, size + 1);
	fread(data, size, 1, fptr);
	fclose(fptr);

	entries = str_split (data, ';');

	portal = entries[0];
	gateway = entries[1];
	user = entries[2];
	cookie = entries[3];

        if (strcmp (vpninfo->hostname, portal) != 0)
          return 1;

        old_hostname = vpninfo->hostname;
	vpninfo->hostname = strdup (gateway);

	ctx.username = strdup (user);
	ctx.portal_userauthcookie = strdup (cookie);
	ctx.reconnect = 1;

	result = gpst_login (vpninfo, 0, &ctx);
        if (result != 0) {
          unlink(tmp_file->data);
        }

	free(vpninfo->hostname);
	vpninfo->hostname = old_hostname;

	free(ctx.username);
	free(ctx.portal_userauthcookie);

	return result;
}

int gpst_obtain_cookie(struct openconnect_info *vpninfo)
{
	struct login_context ctx = { .username=NULL, .alt_secret=NULL, .portal_userauthcookie=NULL, .portal_prelogonuserauthcookie=NULL, .form=NULL };
	char *orig_hostname = NULL;
	int result;

	if (try_reconnect (vpninfo) == 0)
		return 0;

	orig_hostname = g_strdup (vpninfo->hostname);

	/* An alternate password/secret field may be specified in the "URL path" (or --usergroup).
        * Known possibilities are:
	 *     /portal:portal-userauthcookie
	 *     /gateway:prelogin-cookie
	 */
	if (vpninfo->urlpath
	    && (ctx.alt_secret = strrchr(vpninfo->urlpath, ':')) != NULL) {
		*(ctx.alt_secret) = '\0';
		ctx.alt_secret = strdup(ctx.alt_secret+1);
	}

	if (vpninfo->urlpath && (!strcmp(vpninfo->urlpath, "portal") || !strncmp(vpninfo->urlpath, "global-protect", 14))) {
		/* assume the server is a portal */
		result = gpst_login(vpninfo, 1, &ctx);
	} else if (vpninfo->urlpath && (!strcmp(vpninfo->urlpath, "gateway") || !strncmp(vpninfo->urlpath, "ssl-vpn", 7))) {
		/* assume the server is a gateway */
		result = gpst_login(vpninfo, 0, &ctx);
	} else {
		/* first try handling it as a portal, then a gateway */
		result = gpst_login(vpninfo, 1, &ctx);
		if (result == -EEXIST) {
			result = gpst_login(vpninfo, 0, &ctx);
			if (result == -EEXIST)
				vpn_progress(vpninfo, PRG_ERR, _("Server is neither a GlobalProtect portal nor a gateway.\n"));
		}
	}

	if (ctx.reconnect == 0 && result == 0) {
		store_cookie (orig_hostname, vpninfo->hostname, my_user, ctx.portal_userauthcookie);
	}
	free(orig_hostname);
	free(ctx.username);
	free(ctx.alt_secret);
	free(ctx.portal_userauthcookie);
	free(ctx.portal_prelogonuserauthcookie);
	free(ctx.region);
	free_auth_form(ctx.form);
	return result;
}

int gpst_bye(struct openconnect_info *vpninfo, const char *reason)
{
	char *orig_path;
	int result;
	struct oc_text_buf *request_body = buf_alloc();
	char *xml_buf = NULL;

	/* In order to logout successfully, the client must send not only
	 * the session's authcookie, but also the portal, user, computer,
	 * and domain matching the values sent with the getconfig request.
	 *
	 * You read that right: the client must send a bunch of irrelevant
	 * non-secret values in its logout request. If they're wrong or
	 * missing, the logout will fail and the authcookie will remain
	 * valid -- which is a security hole.
	 *
	 * Don't blame me. I didn't design this.
	 */
	buf_append(request_body, "%s", vpninfo->cookie);
	if ((result = buf_error(request_body)))
		goto out;

	/* We need to close and reopen the HTTPS connection (to kill
	 * the tunnel session) and submit a new HTTPS request to
	 * logout.
	 */
	orig_path = vpninfo->urlpath;
	vpninfo->urlpath = strdup("ssl-vpn/logout.esp");
	openconnect_close_https(vpninfo, 0);
	result = do_https_request(vpninfo, "POST", "application/x-www-form-urlencoded", request_body, &xml_buf, NULL, HTTP_NO_FLAGS);
	free(vpninfo->urlpath);
	vpninfo->urlpath = orig_path;

	/* logout.esp returns HTTP status 200 and <response status="success"> when
	 * successful, and all manner of malformed junk when unsuccessful.
	 */
	if (result >= 0)
		result = gpst_xml_or_error(vpninfo, xml_buf, NULL, NULL, NULL);

	if (result < 0)
		vpn_progress(vpninfo, PRG_ERR, _("Logout failed.\n"));
	else
		vpn_progress(vpninfo, PRG_INFO, _("Logout successful.\n"));

out:
	buf_free(request_body);
	free(xml_buf);
	return result;
}

static int parse_callback_file (struct openconnect_info *vpninfo, const char *data_file)
{
	FILE *fptr;
	char *data;
	int len;
	void *xml = NULL;
	xmlDocPtr xml_doc;
	xmlNode *xml_node;
	char *comment = NULL;
	char *prelogin_cookie = NULL;
	char *saml_username = NULL;
	int size;

	/* Open callback data file */
	fptr = fopen(data_file, "r");
	if (!fptr) {
		vpn_progress(vpninfo, PRG_INFO, "Failed to open file %s\n", data_file);
		return -1;
	}

	/* Get file size */
	fseek(fptr, 0L, SEEK_END);
	size = ftell(fptr);
	fseek(fptr, 0L, SEEK_SET);

	/* Read data */
	data = malloc(size + 1);
	memset(data, 0, size + 1);
	fread(data, size, 1, fptr);
	fclose(fptr);

	if (strstr(data, "cas-as=")) {
		char *token = strstr (data, "token=");
		char *un = strstr (data, "un=");

		if (!token || !un) {
			free(data);
			return -1;
		}

		vpn_progress(vpninfo, PRG_INFO, "CAS method for user %s\n", un);

		un += 3;
		saml_username = malloc (token - un - 1);
		if (saml_username) {
			strncpy(saml_username, un, token - un - 1);
			free(vpninfo->sso_username);
			vpninfo->sso_username = saml_username;
			my_user = saml_username;
			vpn_progress(vpninfo, PRG_INFO, "CAS method for user `%s`\n", saml_username);
		}
		token += 6;

		vpninfo->sso_token_cookie = strdup(token);
		free(data);

		return 0;
	}

	vpn_progress(vpninfo, PRG_INFO, "Token method\n");

	xml = openconnect_base64_decode (&len, data);
	free(data);

	vpn_progress(vpninfo, PRG_INFO, "xml (%d): %s\n", len, (char*)xml);

	xml_doc = xmlReadMemory((char*)xml, len, NULL, NULL, XML_PARSE_NOERROR|XML_PARSE_RECOVER);
	free(xml);

	xml_node = xmlDocGetRootElement(xml_doc);
	if (!xml_node)
		return -1;

	for (xmlNode *x = xml_node->children; x; x = x->next) {
		/* Weird protocol response...
		 * <html>
		 *	<!-- <saml-auth-status>1</saml-auth-status>       // Authentication Status 1 = OK
		 *	<prelogin-cookie>TOKEN</prelogin-cookie>          // Prelogin Cookie
		 *	<saml-username>NAME</saml-username>               // Username
		 * 	<saml-slo>no</saml-slo>                           // SAML Single Log-Out (SLO)
		 *	<saml-SessionNotOnOrAfter>2023-11-18T03:13:37.368Z</saml-SessionNotOnOrAfter> // Session Lifetime, used for reconnect
		 * -></html>
		 */
		if (!xmlnode_get_val(x, "comment", &comment)) {
			/* Create a parent xml node for parsing */
			struct oc_text_buf *buf = buf_alloc();

			buf_append(buf, "<parent>%s</parent>", comment);

			xmlDocPtr xml2_doc = xmlReadMemory((char*)buf, buf->pos, NULL, NULL, XML_PARSE_NOERROR|XML_PARSE_RECOVER);
			buf_free(buf);
			xmlNode *xml2_node = xmlDocGetRootElement(xml2_doc);
			if (!xml2_node)
				return -1;

			for (xmlNode *y = xml2_node->children; y; y = y->next) {
				vpn_progress(vpninfo, PRG_DEBUG, "-> Got node: %s\n", y->name);
				xmlnode_get_val(y, "prelogin-cookie", &prelogin_cookie);
				xmlnode_get_val(y, "saml-username", &saml_username);
			}
			xmlFreeDoc(xml2_doc);
		}
	}

	if (saml_username) {
		vpn_progress(vpninfo, PRG_INFO, "saml_username: %s\n", saml_username);
		free(vpninfo->sso_username);
		vpninfo->sso_username = strdup(saml_username);
		my_user = strdup(saml_username);
	}

	if (prelogin_cookie) {
		vpn_progress(vpninfo, PRG_INFO, "prelogin_cookie: %s\n", prelogin_cookie);
		free(vpninfo->sso_token_cookie);
		free(vpninfo->sso_cookie_value);
		vpninfo->sso_token_cookie = strdup("prelogin_cookie");
		vpninfo->sso_cookie_value = strdup(prelogin_cookie);
	}

	return 0;
}

int gpst_handle_external_browser(struct openconnect_info *vpninfo)
{
	struct oc_text_buf *uri = buf_alloc();
	struct oc_text_buf *data_file = buf_alloc();
	struct oc_text_buf *oc_cache_dir = NULL;
	int ret = -1;

	oc_cache_dir = get_user_cache_dir ();

	/* Create data */
	buf_append(data_file, "%s/%s", oc_cache_dir->data, GP_DATA_FILE);

	/* Check whether the sso_login is actually a data field */
	if (strlen(vpninfo->sso_login) > 22 && strncmp(vpninfo->sso_login, "data:text/html;base64,", 22) == 0) {
		int len;
		void *out = openconnect_base64_decode(&len, vpninfo->sso_login + 22);
		struct oc_text_buf *tmp_file = buf_alloc();
		FILE *file;

		vpn_progress(vpninfo, PRG_INFO, "data: %s\n", vpninfo->sso_login);
		if (!out)
			goto finish;

		buf_append(tmp_file, "%s/saml.html", oc_cache_dir->data);
		file = fopen(tmp_file->data, "w");
		if (file) {
			fwrite((char*)out, 1, len, file);
			fclose(file);
		} else {
			vpn_progress(vpninfo, PRG_DEBUG, "Could not write saml.html file\n");
			free(out);
			return -EINVAL;
		}

		free(out);

		buf_append(uri, "file:///%s", tmp_file->data);
		buf_free(tmp_file);
	} else {
		buf_append(uri, "%s", vpninfo->sso_login);
	}

#ifndef _WIN32
	int fd, wd;

	fd = inotify_init();
	if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0)
		goto finish;

	wd = inotify_add_watch(fd, oc_cache_dir->data, IN_CLOSE_WRITE);
	if (wd == -1) {
		vpn_progress(vpninfo, PRG_DEBUG, "Could not watch : %s\n", oc_cache_dir->data);
	} else {
		vpn_progress(vpninfo, PRG_DEBUG, "Watching : %s\n", oc_cache_dir->data);
	}

	if (vpninfo->open_ext_browser) {
		ret = vpninfo->open_ext_browser(vpninfo, uri->data, vpninfo->cbdata);
	} else {
		ret = -EINVAL;
	}

	if (ret) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to spawn external browser for %s\n"),
			     vpninfo->sso_login);
		goto finish;
	}

	/* TODO: Add timeout check to prevent lock up */
	 while (1) {
		int i = 0, length;
		char buffer[BUF_LEN];

		length = read(fd, buffer, BUF_LEN);

		while (i < length) {
 			struct inotify_event *event = (struct inotify_event *) &buffer[i];

			if (event->len) {
				if ((event->mask & IN_CLOSE_WRITE) && !(event->mask & IN_ISDIR) && strcmp(event->name, GP_DATA_FILE) == 0) {
					vpn_progress(vpninfo, PRG_INFO, "The file %s was written.\n", event->name);
					ret = parse_callback_file (vpninfo, data_file->data);
					goto finish;
				}
			}
			i += EVENT_SIZE + event->len;
		}
	}
#else
	vpn_progress(vpninfo, PRG_INFO, "Proper callback data handling missing on Windows\n");
	Sleep(10 * 1000);
	ret = parse_callback_file (vpninfo, data_file);
#endif

finish:
	if (uri)
		buf_free(uri);

	if (oc_cache_dir)
		buf_free(oc_cache_dir);

	if (data_file)
		buf_free(data_file);

	return ret;
}
