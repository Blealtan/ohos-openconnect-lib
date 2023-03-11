// SPDX-License-Identifier: LGPL-2.1-or-later
// Author: Iru Cai <vimacs.hacks@gmail.com>

#include <config.h>

#include "openconnect-internal.h"

#include <assert.h>
#include <libxml/tree.h>
#include <stdbool.h>

static int h3c_request_user_auth(struct openconnect_info *vpninfo, char **username,
				 char **password)
{
	int ret = 0;
	struct oc_auth_form *form = calloc(1, sizeof(struct oc_auth_form));
	if (!form) {
		goto nomem;
	}
	form->auth_id = strdup("_login");
	form->message = strdup("Enter user credentials:");

	struct oc_form_opt *opt_user = calloc(1, sizeof(struct oc_form_opt));
	if (!opt_user) {
		goto nomem;
	}
	form->opts = opt_user;

	opt_user->name = strdup("username");
	if (!opt_user->name) {
		goto nomem;
	}
	opt_user->label = strdup("Username: ");
	if (!opt_user->label) {
		goto nomem;
	}
	opt_user->type = OC_FORM_OPT_TEXT;
	opt_user->next = NULL;

	struct oc_form_opt *opt_pass = calloc(1, sizeof(struct oc_form_opt));
	if (!opt_pass) {
		goto nomem;
	}
	opt_user->next = opt_pass;

	opt_pass->name = strdup("password");
	if (!opt_pass->name) {
		goto nomem;
	}
	opt_pass->label = strdup("Password: ");
	if (!opt_pass->label) {
		goto nomem;
	}
	opt_pass->type = OC_FORM_OPT_PASSWORD;
	opt_pass->next = NULL;

	ret = process_auth_form(vpninfo, form);
	if (ret != 0) {
		return ret;
	}

	*username = opt_user->_value;
	*password = opt_pass->_value;
	opt_user->_value = opt_pass->_value = NULL;

out:
	if (form) {
		free_auth_form(form);
	}
	return ret;
nomem:
	ret = -ENOMEM;
	goto out;
}

static int h3c_get_vpn_param_from_headers(struct openconnect_info *vpninfo, char *k, char *v)
{
	bool set_value = true;
	if (!strcmp(k, "IPADDRESS")) {
		vpninfo->ip_info.addr = strdup(v);
	} else if (!strcmp(k, "SUBNETMASK")) {
		int masklen = atoi(v);
		struct in_addr mask_addr;
		char abuf[INET_ADDRSTRLEN];

		if (masklen)
			mask_addr.s_addr = htonl(0xffffffff << (32 - masklen));
		else /* Shifting by 32 is invalid, so special-case it */
			mask_addr.s_addr = 0;

		inet_ntop(AF_INET, &mask_addr, abuf, sizeof(abuf));
		vpninfo->ip_info.netmask = strdup(abuf);
	} else if (!strcmp(k, "ROUTES")) {
		// ROUTES: ip/mask;ip/mask;...;ip/mask
		const char *vp = v;
		while (*vp != 0) {
			const char *scanpos = vp;
			while (*scanpos != 0 && *scanpos != ';') {
				++scanpos;
			}
			if (scanpos != vp) {
				struct oc_split_include *route =
					(struct oc_split_include *)malloc(
						sizeof(struct oc_split_include));
				route->route = strndup(vp, scanpos - vp);
				route->next = vpninfo->ip_info.split_includes;
				vpninfo->ip_info.split_includes = route;
			}
			vp = scanpos + 1;
		}
	} else {
		set_value = false;
	}
	if (set_value && vpninfo->dump_http_traffic) {
		char buf[1000];
		strcpy(buf, k);
		strcat(buf, ":");
		strcat(buf, v);
		dump_buf(vpninfo, '<', buf);
	}

	return 0;
}

static int h3c_store_location_action_from_headers(struct openconnect_info *vpninfo, char *k,
						  char *v)
{
	if (strcmp(k, "Location-Action") == 0) {
		add_option_dup(&vpninfo->cstp_options, "Location-Action", v, -1);
	}
	return 0;
}

static void h3c_parse_domain_list(struct openconnect_info *vpninfo, const char *domain_list_str,
				  char **gateway_info_str_ptr)
{
	xmlDocPtr xml_doc = xmlReadMemory(domain_list_str, strlen(domain_list_str), NULL, NULL,
					  XML_PARSE_NOERROR);
	assert(xml_doc);

	/*Get the root element node */
	xmlNode *root_element = xmlDocGetRootElement(xml_doc);

	// now we only use the first domain
	char *vpn_name = NULL, *vpn_url = NULL;

	// print_element_names(root_element);
	// <data> ... </data>
	if (xmlnode_is_named(root_element, "data")) {
		// find <domainlist> ... </domainlist>
		for (xmlNode *dom_list_node = root_element->children; dom_list_node;
		     dom_list_node = dom_list_node->next) {
			if (xmlnode_is_named(dom_list_node, "domainlist")) {
				// find <domain> ... </domain>
				for (xmlNode *dom = dom_list_node->children; dom;
				     dom = dom->next) {
					if (xmlnode_is_named(dom, "domain")) {
						for (xmlNode *dom_prop = dom->children;
						     dom_prop; dom_prop = dom_prop->next) {
							if (xmlnode_is_named(dom_prop,
									     "name")) {
								xmlnode_get_val(dom_prop,
										"name",
										&vpn_name);
							}
							if (xmlnode_is_named(dom_prop, "url")) {
								xmlnode_get_val(dom_prop, "url",
										&vpn_url);
							}
							if (vpn_name != NULL
							    && vpn_url != NULL) {
								goto get_domain_success;
							}
						}
					}
				}
			}
		}
	}

get_domain_success:
	assert(vpn_name != NULL && vpn_url != NULL);
	if (vpn_url[0] == '/') {
		vpninfo->urlpath = strdup(vpn_url + 1);
	} else {
		vpninfo->urlpath = strdup(vpn_url);
	}
	struct oc_text_buf *reqbuf = buf_alloc();
	int ret = do_https_request(vpninfo, "GET", NULL, reqbuf, gateway_info_str_ptr, NULL,
				   HTTP_BODY_ON_ERROR);
	assert(ret >= 0);
	buf_free(reqbuf);
}

static bool check_login_success(struct openconnect_info *vpninfo, const char *xmlstr)
{
	if (!xmlstr)
		return false;

	xmlDocPtr login_result_xml =
		xmlReadMemory(xmlstr, strlen(xmlstr), NULL, NULL, XML_PARSE_NOERROR);
	if (!login_result_xml)
		return false;

	xmlNode *login_result_root = xmlDocGetRootElement(login_result_xml);

	/*
	 * the login API return the following XML:
	 * <data>
	 *   <result>
	 *     Success or Failed
	 *   </result>
	 *   <replyMessage> ... </replyMessage>
	 *   <private> ... </private>
	 * </data>
	 */
	char *result_string = NULL;
	char *reply_message = NULL;
	bool login_success;

	if (xmlnode_is_named(login_result_root, "data")) {
		for (xmlNode *res_node = login_result_root->children; res_node;
		     res_node = res_node->next) {
			xmlnode_get_val(res_node, "result", &result_string);
			xmlnode_get_val(res_node, "replyMessage", &reply_message);
		}
	}
	if (result_string && strstr(result_string, "Success")) {
		login_success = true;
	} else {
		login_success = false;
		if (reply_message) {
			vpn_progress(vpninfo, PRG_ERR, _("Login error: %s\n"), reply_message);
		}
	}
	if (result_string)
		free(result_string);

	if (reply_message)
		free(reply_message);

	xmlFreeDoc(login_result_xml);
	return login_success;
}

int h3c_obtain_cookie(struct openconnect_info *vpninfo)
{
	int ret;

	ret = openconnect_open_https(vpninfo);
	if (ret) {
		return ret;
	}

	assert(vpninfo->ssl_write);

	struct oc_text_buf *reqbuf = buf_alloc();

	buf_append(reqbuf, "GET /svpn/index.cgi HTTP/1.1\r\n");
	char *orig_ua = vpninfo->useragent;
	// The H3C client uses this UA on the first access
	vpninfo->useragent = (char *)"SSLVPN-Client/3.0";
	http_common_headers(vpninfo, reqbuf);
	vpninfo->useragent = orig_ua;
	buf_append(reqbuf, "\r\n");

	if (buf_error(reqbuf)) {
		vpn_progress(vpninfo, PRG_ERR, _("Error creating H3C connection request\n"));
		ret = buf_error(reqbuf);
		goto obtain_cookie_out;
	}
	if (vpninfo->dump_http_traffic) {
		dump_buf(vpninfo, '>', reqbuf->data);
	}

	ret = vpninfo->ssl_write(vpninfo, reqbuf->data, reqbuf->pos);
	if (ret < 0) {
		goto obtain_cookie_out;
	}

	struct oc_text_buf *resp_buf = buf_alloc();
	assert(resp_buf);
	if (buf_error(resp_buf)) {
		ret = buf_free(resp_buf);
		goto obtain_cookie_out;
	}

	ret = process_http_response(vpninfo, 1, h3c_store_location_action_from_headers,
				    resp_buf);

	bool has_domain_list = false;
	for (struct oc_vpn_option *opt = vpninfo->cstp_options; opt != NULL; opt = opt->next) {
		if (strcmp(opt->option, "Location-Action") == 0) {
			if (strcmp(opt->value, "GetDomainList") == 0) {
				has_domain_list = true;
			}
			break;
		}
	}

	char *gateway_info_str = NULL;

	if (has_domain_list) {
		char *domain_list_str = NULL;
		if (ret == 302) {
			ret = handle_redirect(vpninfo);
			if (ret == 0) {
				buf_truncate(reqbuf);
				ret = do_https_request(vpninfo, "GET", NULL, reqbuf,
						       &domain_list_str, NULL, HTTP_REDIRECT);
				if (ret > 0) {
					assert(domain_list_str != NULL);
					dump_buf(vpninfo, '<', domain_list_str);
				}
			}
		}
		assert(domain_list_str);
		h3c_parse_domain_list(vpninfo, domain_list_str, &gateway_info_str);
	} else {
		if (ret == 302) {
			ret = handle_redirect(vpninfo);
			if (ret == 0) {
				buf_truncate(reqbuf);
				ret = do_https_request(vpninfo, "GET", NULL, reqbuf,
						       &gateway_info_str, NULL, HTTP_REDIRECT);
				assert(ret > 0);
			}
		}
	}

	assert(gateway_info_str != NULL);

	char *login_url = NULL;
	char *logout_url = NULL;
	char *checkonline_url = NULL;
	char *challenge_url = NULL;
	xmlDocPtr gwinfo_xml = xmlReadMemory(gateway_info_str, strlen(gateway_info_str), NULL,
					     NULL, XML_PARSE_NOERROR);
	assert(gwinfo_xml);
	xmlNode *gwinfo_root = xmlDocGetRootElement(gwinfo_xml);
	assert(gwinfo_root);
	// <data> ... </data>
	if (xmlnode_is_named(gwinfo_root, "data")) {
		// find <gatewayinfo> ... </gatewayinfo>
		for (xmlNode *gw_node = gwinfo_root->children; gw_node;
		     gw_node = gw_node->next) {
			if (xmlnode_is_named(gw_node, "gatewayinfo")) {
				// we ignore <auth> ... </auth>, just find <url> ... </url>
				for (xmlNode *url_nodes = gw_node->children; url_nodes;
				     url_nodes = url_nodes->next) {
					if (xmlnode_is_named(url_nodes, "url")) {
						for (xmlNode *method_url = url_nodes->children;
						     method_url;
						     method_url = method_url->next) {
							xmlnode_get_val(method_url, "login",
									&login_url);
							xmlnode_get_val(method_url, "logout",
									&logout_url);
							xmlnode_get_val(method_url,
									"checkonline",
									&checkonline_url);
							xmlnode_get_val(method_url, "challenge",
									&challenge_url);
						}
						if (login_url != NULL && logout_url != NULL
						    && checkonline_url != NULL
						    && challenge_url != NULL) {
							goto do_visit_login_url;
						}
					}
				}
			}
		}
	}

do_visit_login_url:
	if (login_url == NULL || logout_url == NULL || checkonline_url == NULL
	    || challenge_url == NULL) {
		return -EINVAL;
	}

	if (login_url[0] == '/') {
		add_option_dup(&vpninfo->cstp_options, "login_url", login_url + 1, -1);
	} else {
		add_option_dup(&vpninfo->cstp_options, "login_url", login_url, -1);
	}
	if (logout_url[0] == '/') {
		add_option_dup(&vpninfo->cstp_options, "logout_url", logout_url + 1, -1);
	} else {
		add_option_dup(&vpninfo->cstp_options, "logout_url", logout_url, -1);
	}
	if (checkonline_url[0] == '/') {
		add_option_dup(&vpninfo->cstp_options, "checkonline_url", checkonline_url + 1,
			       -1);
	} else {
		add_option_dup(&vpninfo->cstp_options, "checkonline_url", checkonline_url, -1);
	}
	if (challenge_url[0] == '/') {
		add_option_dup(&vpninfo->cstp_options, "challenge_url", challenge_url + 1, -1);
	} else {
		add_option_dup(&vpninfo->cstp_options, "challenge_url", challenge_url, -1);
	}

	char *username = NULL, *password = NULL;
	assert(h3c_request_user_auth(vpninfo, &username, &password) == 0);
	assert(login_url != NULL && logout_url != NULL && checkonline_url != NULL
	       && challenge_url != NULL);
	if (login_url[0] == '/') {
		vpninfo->urlpath = strdup(login_url + 1);
	} else {
		vpninfo->urlpath = strdup(login_url);
	}
	buf_truncate(reqbuf);
	struct oc_text_buf *request_data = buf_alloc();
	buf_append(request_data, "request=");
	buf_append_urlencoded(request_data, "<data><username>");
	buf_append_urlencoded(request_data, username);
	buf_append_urlencoded(request_data, "</username><password>");
	buf_append_urlencoded(request_data, password);
	buf_append_urlencoded(request_data, "</password></data>\r\n");
	char *login_resp = NULL;
	ret = do_https_request(vpninfo, "POST", "application/x-www-form-urlencoded",
			       request_data, &login_resp, NULL, HTTP_BODY_ON_ERROR);
	if (ret >= 0 && login_resp != NULL) {
		dump_buf(vpninfo, '<', login_resp);
	}

	bool login_success = check_login_success(vpninfo, login_resp);
	if (!login_success) {
		ret = -EPERM;
		goto obtain_cookie_out;
	}

	for (struct oc_vpn_option *cookie = vpninfo->cookies; cookie; cookie = cookie->next) {
		if (!strcmp(cookie->option, "svpnginfo")) {
			free(vpninfo->cookie);
			if (asprintf(&vpninfo->cookie, "svpnginfo=%s", cookie->value) < 0) {
				ret = -ENOMEM;
				goto obtain_cookie_out;
			}
			ret = 0;
			goto obtain_cookie_out;
		}
	}

	// if svpnginfo cookie is not found, make the login fail
	ret = -EPERM;

obtain_cookie_out:
	return ret;
}

int h3c_connect(struct openconnect_info *vpninfo)
{
	if (!vpninfo->cookies) {
		int ret = internal_split_cookies(vpninfo, 1, "svpnginfo");
		if (ret)
			return ret;
	}

	struct oc_text_buf *request_data = buf_alloc();
	vpninfo->urlpath = (char *)"";
	char *handshake_resp = NULL;
	do_https_request(vpninfo, "NET_EXTEND", NULL, request_data, &handshake_resp,
			 h3c_get_vpn_param_from_headers, HTTP_BODY_ON_ERROR);

	monitor_fd_new(vpninfo, ssl);
	monitor_read_fd(vpninfo, ssl);
	monitor_except_fd(vpninfo, ssl);
	vpninfo->ip_info.mtu = 1400;

	buf_free(request_data);
	return 0;
}

int h3c_bye(struct openconnect_info *vpninfo, const char *reason)
{
	openconnect_close_https(vpninfo, 0);

	char *logout_url = NULL;
	for (struct oc_vpn_option *opt = vpninfo->cstp_options; opt != NULL; opt = opt->next) {
		if (strcmp(opt->option, "logout_url") == 0) {
			logout_url = opt->value;
		}
	}

	if (logout_url != NULL) {
		char *logout_resp = NULL;
		vpninfo->urlpath = strdup(logout_url);
		int ret = do_https_request(vpninfo, "GET", NULL, NULL, &logout_resp, NULL,
					   HTTP_BODY_ON_ERROR);
		return ret;
	}
	return -EINVAL;
}

static void h3c_handle_outgoing(struct openconnect_info *vpninfo)
{
	vpninfo->ssl_times.last_tx = time(NULL);
	unmonitor_write_fd(vpninfo, ssl);

	vpn_progress(vpninfo, PRG_TRACE, _("Packet outgoing:\n"));
	store_le16(&vpninfo->current_ssl_pkt->h3c.type, 1);
	store_be16(&vpninfo->current_ssl_pkt->h3c.len, vpninfo->current_ssl_pkt->len);
	int ret = ssl_nonblock_write(vpninfo, 0, &vpninfo->current_ssl_pkt->h3c.type,
				     vpninfo->current_ssl_pkt->len + 4);
	if (ret < 0) {
		vpn_progress(vpninfo, PRG_ERR, _("Send packet failed\n"));
		/* TODO: we don't know what to do now */
	}
}

int h3c_mainloop(struct openconnect_info *vpninfo, int *timeout, int readable)
{
	while (readable) {
		/* Some servers send us packets that are larger than
		   negotiated MTU. We reserve some extra space to
		   handle that */
		int receive_mtu = MAX(16384, vpninfo->deflate_pkt_size ?: vpninfo->ip_info.mtu);
		int len;

		if (!vpninfo->cstp_pkt) {
			vpninfo->partial_rec_size = 0;
			vpninfo->cstp_pkt = alloc_pkt(vpninfo, receive_mtu);
			if (!vpninfo->cstp_pkt) {
				vpn_progress(vpninfo, PRG_ERR, _("Allocation failed\n"));
				break;
			}
		}

		len = ssl_nonblock_read(vpninfo, 0,
					vpninfo->cstp_pkt->data + vpninfo->partial_rec_size,
					receive_mtu - vpninfo->partial_rec_size);
		if (!len)
			break;
		if (len < 0) {
			/* goto do_reconnect; */
			return -1;
		}

		if (vpninfo->partial_rec_size) {
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Received %d more bytes after partial %d\n"), len,
				     vpninfo->partial_rec_size);
			len += vpninfo->partial_rec_size;
			vpninfo->partial_rec_size = len;
		}

		vpninfo->ssl_times.last_rx = time(NULL);

		unsigned char *buf = vpninfo->cstp_pkt->data;

		if (buf[0] == 1) {
			uint16_t iplen = load_be16(buf + 2);
			if (len - 4 >= iplen) {
				if (len - 4 != iplen) {
					dump_buf_hex(vpninfo, PRG_DEBUG, '>', buf, len);
				}
				memmove(buf, buf + 4, len - 4);
				vpninfo->cstp_pkt->len = len - 4;
				vpninfo->partial_rec_size = 0;
				vpn_progress(vpninfo, PRG_TRACE,
					     _("Moved down %d bytes after previous packet\n"),
					     len);
			}
		} else {
			dump_buf_hex(vpninfo, PRG_ERR, '>', buf, len);
		}

		queue_packet(&vpninfo->incoming_queue, vpninfo->cstp_pkt);
		vpninfo->cstp_pkt = NULL;
	}

	if (vpninfo->current_ssl_pkt) {
		/* TODO: we don't know what to do yet */
		h3c_handle_outgoing(vpninfo);
		vpninfo->current_ssl_pkt = NULL;
	}

	while ((vpninfo->current_ssl_pkt = dequeue_packet(&vpninfo->outgoing_queue))) {
		h3c_handle_outgoing(vpninfo);
	}
	return 1;
}

void h3c_http_headers(struct openconnect_info *vpninfo, struct oc_text_buf *buf)
{
	char *orig_ua = vpninfo->useragent;
	vpninfo->useragent = (char *)"SSLVPN-Client/7.0";
	http_common_headers(vpninfo, buf);
	vpninfo->useragent = orig_ua;
}
