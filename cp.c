/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2020-2021 Nick Krylov.
 * Copyright © 2021 Daniel Lenski.
 *
 * Author: Nick Krylov <krylovna@gmail.com>
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

#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdarg.h>

#include "openconnect-internal.h"

#define FREE(ptr) do{free(ptr);ptr=NULL;}while(0)
#define FREE_PASS(ptr) do{free_pass(&ptr);}while(0)

enum PACKET_TYPE {
	CMD = 1,
	DATA
};

static const int hdr_len = sizeof(((struct pkt*)NULL)->cpsnx.hdr);

static char clients_str[] = "/clients/";
static char awaiting_hello_reply[] = "Awaiting hello_reply";

/* Strange initialisers here to work around GCC PR#10676 (which was
 * fixed in GCC 4.6 but it takes a while for some systems to catch
 * up. */
static const struct pkt keepalive_pkt = {
	.next = NULL,
	{ .cpsnx.hdr = { 0, 0, 0, 25, 0, 0, 0, CMD } },
	.len=25,
	.data = "(keepalive\n    :id (0)\n)", /* XX: 25 bytes, including final '\0' */
};

/* CCC protocol commands */

static const char CCCclientRequestClientHello[] = "(CCCclientRequest\n\
    :RequestHeader (\n\
        :id (1)\n\
        :session_id ()\n\
        :type (ClientHello)\n\
        :protocol_version (100)\n\
    )\n\
    :RequestData (\n\
        :client_info (\n\
        :client_type (TRAC)\n\
        :client_version (%d)\n\
        :gw_ip (%s)\n\
        )\n\
    )\n\
)";

static const char CCCclientRequestUserPass[] = "(CCCclientRequest\n\
    :RequestHeader (\n\
        :id (2)\n\
        :type (UserPass)\n\
        :session_id ()\n\
    )\n\
    :RequestData (\n\
        :client_type (TRAC)\n";

static const char CCCclientRequestCert[] = "(CCCclientRequest\n\
    :RequestHeader (\n\
        :id (1)\n\
        :type (CertAuth)\n\
        :session_id ()\n\
    )\n\
    :RequestData (\n\
        :client_type (TRAC)\n\
    )\n\
)";

static const char CCCclientRequestSignout[] = "(CCCclientRequest\n\
	:RequestHeader (\n\
		:id (0)\n\
		:type (Signout)\n\
		:session_id (%s)\n\
		:protocol_version (100)\n\
	)\n\
	:RequestData ()\n\
)\n";

/* SLIM protocol commands */
static const char client_hello[] = "(client_hello\n\
        :client_version (%d)\n\
        :protocol_version (%d)\n\
        :OM (\n\
                :ipaddr (%s)\n\
                :keep_address (%s)\n\
        )\n\
        :optional (\n\
                :client_type (4)\n\
        )\n\
        :cookie (%s)\n\
)";

static const char disconnect[] = "(disconnect\n\
        :code (28)\n\
        :message (\"User has disconnected.\")\n\
)";

static struct pkt *build_packet(struct openconnect_info *vpninfo, int type, const void *data, int len)
{
	struct pkt *p = alloc_pkt(vpninfo, len);
	if (!p)
		return NULL;
	p->len = len;
	store_be32(p->cpsnx.hdr + 4, type);
	memcpy(p->data, data, len);
	return p;
}

/* Special handling for commands: hide authentication-related fields */
#ifndef INSECURE_DEBUGGING
static char *hide_auth_data(const char *data)
{
	static const char *excl_fields[] = {"username", "password", "cookie", "active_key", "session_id"};
	char *val_start, *val_end, *ret = strdup(data);
	const char *fld, *fld_start;
	int i;
	if (!ret)
		return NULL;

	for (i = 0; i < sizeof (excl_fields) / sizeof (*excl_fields); i++) {
		fld = excl_fields[i];
		fld_start = ret;
		while ((fld_start = strstr(fld_start, fld))) {
			val_start = strstr(fld_start, "(");
			if (!val_start)
				continue;
			if (fld_start[strlen(fld)] == ' ') {
				val_end = strstr(fld_start, ")");
				if (val_end > (val_start + 1)) {
					memmove(val_start + 2, val_end, strlen(val_end) + 1); /* include \0 */
					val_start[1] = 'X'; /* Hide string, but mark as not empty*/
				}
			}
			fld_start++;
		}
	}
	return ret;
}
#endif

static int snx_queue_command(struct openconnect_info *vpninfo, const char*cmd)
{
	int len = strlen(cmd) + 1;
	struct pkt *pkt = build_packet(vpninfo, CMD, cmd, len);
	if (!pkt)
		return -ENOMEM;
	return queue_packet(&vpninfo->tcp_control_queue, pkt);
}

static int snx_receive(struct openconnect_info *vpninfo, int*pkt_type) {
	int ret;
	uint8_t *buf;
	struct pkt *pkt = vpninfo->cstp_pkt;
	int receive_mtu = MAX(16384, vpninfo->ip_info.mtu);

	if (!pkt) {
		pkt = vpninfo->cstp_pkt = alloc_pkt(vpninfo, receive_mtu);
		if (!pkt)
			return -ENOMEM;
		pkt->len = 0;
	}

	/* FIXME: check that packet size does not exceed receive_mtu */

	/* Read header */
	if (pkt->len == 0) {
		int len_rec = hdr_len - vpninfo->partial_rec_size;
		buf = pkt->cpsnx.hdr + vpninfo->partial_rec_size;
		ret = ssl_nonblock_read(vpninfo, 0, buf, len_rec);

		if (ret < 0) {
			/* Exit immediately on error. */
			free_pkt(vpninfo, vpninfo->cstp_pkt);
			vpninfo->cstp_pkt = NULL;
			return ret;
		}


		if (ret + vpninfo->partial_rec_size < hdr_len) {
			vpninfo->partial_rec_size += ret;
			return -EAGAIN;
		}

		pkt->len = load_be32(pkt->cpsnx.hdr);
		pkt = vpninfo->cstp_pkt;
		vpninfo->partial_rec_size = 0;
	}

	/* Read payload */
	*pkt_type = load_be32(pkt->cpsnx.hdr + 4);
	int payload_len = pkt->len - vpninfo->partial_rec_size;
	buf = pkt->data + vpninfo->partial_rec_size;
	/* Prevent (unlikely) buffer overflow */
	if (payload_len > pkt->alloc_len - sizeof (*pkt))
		return -E2BIG;

	ret = ssl_nonblock_read(vpninfo, 0, buf, payload_len);

	if (ret < 0) {
		free_pkt(vpninfo, vpninfo->cstp_pkt);
		/* Exit immediately on error. */
		return ret;
	}

	if (ret + vpninfo->partial_rec_size < payload_len) {
		vpninfo->partial_rec_size += ret;
		return -EAGAIN;
	}

	/* We have finally received full packet */
	vpninfo->partial_rec_size = 0;
	vpninfo->ssl_times.last_rx = time(NULL);

	if (vpninfo->verbose >= PRG_DEBUG) {
		if (*pkt_type == DATA) {
			vpn_progress(vpninfo, PRG_TRACE, _("Received data packet of %d bytes.\n"),
				     payload_len);
			dump_buf_hex(vpninfo, PRG_TRACE, '<', (void *) &vpninfo->cstp_pkt->cpsnx.hdr, payload_len + hdr_len);
		} else if (*pkt_type == CMD) {
			char *cmd = (char *) vpninfo->cstp_pkt->data;
			/* XX: hide_auth_data, snx_handle_command, and vpn_progress (immediately below)
			 * all assume this is a null-terminated command. We need to ensure that it is.
			 */
			cmd[vpninfo->cstp_pkt->len - 1] = '\0';
#ifdef INSECURE_DEBUGGING
			vpn_progress(vpninfo, PRG_DEBUG, _("Command received:\n%s\n"), cmd);
#else
			char *cmd_print = hide_auth_data(cmd);
			vpn_progress(vpninfo, PRG_DEBUG, _("Command received:\n%s\n"), cmd_print);
			free(cmd_print);
#endif
		}
	}
	return ret;
}

/* NOTE: Legacy IP versions */
static uint32_t strtoipv4(const char *ip)
{
	uint32_t ret = 0;
	struct in_addr buf;
	if (inet_pton(AF_INET, ip, &buf) == 1)
		ret = ntohl(buf.s_addr);
	return ret;
}

/* Authentication-related helpers. */
static
int enc_dec_table[] = {
	0x2D, 0x4F, 0x44, 0x49, 0x46, 0x49, 0x45, 0x44, 0x26, 0x57, 0x30, 0x52, 0x4F, 0x50, 0x45, 0x52,
	0x54, 0x59, 0x33, 0x48, 0x45, 0x45, 0x54, 0x37, 0x49, 0x54, 0x48, 0x2F, 0x2B, 0x34, 0x48, 0x45,
	0x33, 0x48, 0x45, 0x45, 0x54, 0x29, 0x24, 0x33, 0x3F, 0x2C, 0x24, 0x21, 0x30, 0x3F, 0x21, 0x35,
	0x3F, 0x30, 0x32, 0x2F, 0x30, 0x25, 0x32, 0x34, 0x29, 0x25, 0x33, 0x2E, 0x35, 0x2C, 0x2C, 0x10,
	0x26, 0x37, 0x3F, 0x37, 0x30, 0x3F, 0x2F, 0x22, 0x2A, 0x25, 0x23, 0x34, 0x33, 0x00, 0x00, 0x00, /* enc_dec_table[0x4c] is last non-zero value */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static
uint8_t enc_dec_ichr(int i, uint8_t ordc)
{
	uint8_t ret;

	/* MSB is bit 29. This value very nearly divides 2^36 (0x100000000):
	 * (0x1000000000 / 0x3531DEC1 = 0x4C.FFFFFFC17
	 * This means that bits >=36 of prod increment with every increase
	 * of i by 0x4d.
	 */
	uint64_t magic = 0x3531DEC1;
	uint64_t prod = (((uint64_t) i) * magic);

	/* high_bits = 0 if       0 <= i < 1*0x04d
	 *           = 1 if 1*0x04d <= i < 2*0x04d
	 *           = 2 if 2*0x04d <= i < 3*0x04d
	 *           ...
	 */
	uint64_t high_bits = prod >> (32 + 4);

	/* idx is always in the range [0, 0x4c] */
	int idx = i - 0x4d * high_bits;

	/* Encoding and decoding are identical because ordc is XOR'ed with
	 * a function that depends only on i (the position in the string).
	 * The byte 0 cannot be used as input because it will be change to
	 * 0xff by a round-trip of encoding then decoding.
	 */
	if (ordc == 0xff)
		ordc = 0;
	ret = ((enc_dec_table[idx] ^ ordc));
	if (ret == 0)
		ret = 0xff;

	return ret;
}

static int buf_append_scrambled(struct oc_text_buf *buf, const char *s)
{
	int i, slen = strlen(s);

	for (i = slen - 1; i >= 0; i--)
		buf_append(buf, "%02x", enc_dec_ichr(i, (uint8_t) s[i]));
	return buf_error(buf);
}

static char *unscramble(char *s)
{
	int i, slen = strlen(s), retlen = slen >> 1;
	char *ret = malloc(retlen + 1);

	if (!ret)
		return NULL;
	else if (slen & 1) {
		FREE_PASS(ret);
		return NULL;
	}

	for (i = 0; i < retlen; i++)
		ret[i] = enc_dec_ichr(i, unhex(s + slen - 2 - (i << 1)));
	ret[retlen] = 0;
	return ret;
}

/* Options handling helpers. Needed for server response processing.
 * Unfortunately, option syntax is not standard http/xml, but a special one.
 * Fortunately, it is not that complicated.*/

struct cp_option {
	char *key, *value;
	int parent;
};

typedef struct cp_option cp_option;

struct cp_options {
	char *rawdata;
	int len;
	cp_option elems[];
};

typedef struct cp_options cp_options;

static cp_options *cpo_init(int ne)
{
	cp_options *cfg = (cp_options *) calloc(1, sizeof (cp_options) + ne * sizeof (cp_option));
	if (cfg)
		cfg->len = ne;
	return cfg;
}

static void cpo_free(cp_options *cfg)
{
	if (!cfg) return;
	free_pass(&cfg->rawdata);
	free(cfg);
}

static int cpo_parse_elem(cp_options *cfg, char **input_ptr, int pidx, int *nextidx)
{
	char *nl = NULL, *strstart, *strend = NULL, *colon = NULL, *obrkt = NULL;
	char *cbrkt = NULL, *key;
	int idx, vlen, good, previdx;
	struct cp_option *cfge;
	char *input = *input_ptr;

	colon = strchr(input, ':');
	cbrkt = strchr(input, ')');
	if (colon && cbrkt > colon) {
		obrkt = strchr(colon, '(');
		strstart = strstr(colon, "(\"");

		if (strstart && strstart == obrkt) {
			/* Adjust nl */
			strend = strstr(colon, "\")");
			nl = strend + 2;
		} else {
			cbrkt = strchr(colon, ')');
			nl = strchr(colon, '\n');
			if (nl < cbrkt)
				cbrkt = NULL;
		}
	} else {
		colon = NULL;
		/* After last element */
		cbrkt = strchr(input, ')');
		if (cbrkt)
			nl = strchr(cbrkt, '\n');
	}
	if (!nl)
		return 0;
	nl[0] = 0;

	*input_ptr = nl + 1;

	idx = *nextidx;
	cfge = cfg->elems + idx;
	if (colon) {
		(*nextidx)++;
		key = colon + 1;
		/* Save non-empty keys only */
		if (key[0] != ' ') {
			cfge->key = key;
			key[obrkt - key - 1] = 0;
		}

		cfge->parent = pidx;
		if (obrkt) {
			if (cbrkt) {
				/* Single element. Save value. */
				cfge->value = obrkt + 1;
				vlen = cbrkt - cfge->value;
				cfge->value[vlen] = 0;

				/* Drop quotes if string is quoted */
				if (strstart && strend) {
					cfge->value[vlen - 1] = 0;
					cfge->value++;
				}
				return 1;
			} else {
				/* Container (list|map) */
				previdx = *nextidx;
				while ((good = cpo_parse_elem(cfg, input_ptr, idx, nextidx))&&(previdx<*nextidx))
					previdx = *nextidx;
				return good;
			}
		}
	} else if (cbrkt)
		return 1; /* Container end */
	return 0;
}

static cp_options *cpo_parse(const char *input)
{
	if (!input)
		return NULL;
	size_t full_len = strlen(input);
	if (full_len < 3)
		return NULL;

	/* Count number of elements in input data which is equal to the amount
	 * of ':' characters in the input string.*/

	const char *ptr = input;
	cp_options *cfg;
	int nelem, nextidx, ok = 0;
	for (nelem = 0; (ptr = strchr(ptr, ':')); nelem++, ptr++);

	cfg = cpo_init(nelem + 1);
	if (cfg) {
		char *key, *next, *data = strdup(input);
		if (data) {
			const char *dataend = data + full_len - 1;
			cfg->rawdata = data;
			next = data;
			key = next + 1; /* Drop leading '(' */
			cfg->elems[0].key = key;
			next = strchr(key, '\n');
			nextidx = 1;
			ok = next != NULL;
			/* Do recursive parsing */
			if (ok) {
				key[next - key] = 0;
				next++;
				while ((ok = cpo_parse_elem(cfg, &next, 0, &nextidx))&&(next < dataend));
			}
		}
		if (!ok) {
			cpo_free(cfg);
			cfg = NULL;
		}
	}
	return cfg;
}

static int cpo_find_child(const cp_options *cfg, int pidx, const char *key)
{
	int elemidx = -1;
	int ne = cfg->len;
	if (pidx >= 0) {
		for (int ie = pidx + 1; ie < ne; ie++) {
			const cp_option *elem = &cfg->elems[ie];
			if (elem->parent == pidx && elem->key && (0 == strcmp(key, elem->key))) {
				elemidx = ie;
				break;
			}
		}
	}
	return elemidx;
}

static int cpo_elem_iter(const cp_options *cfg, int iparent, int *i)
{

	int found = 0;
	if (iparent < 0)
		return found;
	if (*i < 0)
		*i = iparent;
	else
		++(*i);

	for (; *i < cfg->len; ++(*i)) {
		const cp_option *nextelem = &cfg->elems[*i];
		if (nextelem->parent == iparent) {
			found = 1;
			break;
		}
	}
	return found;
}

static const cp_option *cpo_get(const cp_options *cfg, int i)
{
	return (i >= 0) ? &cfg->elems[i] : NULL;
}

static int cpo_get_index(const cp_options *cfg, const cp_option *opt)
{
	return opt ? opt - cfg->elems : -1;
}

static int https_request_wrapper(struct openconnect_info *vpninfo, struct oc_text_buf *request_body,
				 char **resp_buf, int rdrfetch)
{
	int result;
	const char *method = request_body ? "POST" : "GET";
	const char *req_type = request_body ? "application/x-www-form-urlencoded" : NULL;

#ifndef INSECURE_DEBUGGING
	int dump_http_traffic = vpninfo->dump_http_traffic;

	if (request_body && vpninfo->verbose >= PRG_DEBUG) {
		char*cmd_print = hide_auth_data(request_body->data);
		vpn_progress(vpninfo, PRG_DEBUG, _("HTTP post data:\n%s\n"), cmd_print);
		free(cmd_print);
	}

	vpninfo->dump_http_traffic = 0; /* Do not print sensitive info */
#endif

	result = do_https_request(vpninfo, method, req_type, request_body, resp_buf, NULL, rdrfetch);

#ifndef INSECURE_DEBUGGING
	if (*resp_buf && vpninfo->verbose >= PRG_DEBUG) {
		char *cmd_print = hide_auth_data(*resp_buf);
		vpn_progress(vpninfo, PRG_DEBUG, _("HTTP response data:\n%s\n"), cmd_print);
		free(cmd_print);
	}
	vpninfo->dump_http_traffic = dump_http_traffic;
#endif
	return result;
}

static const cp_option *get_from_rd(const cp_options *cpo, const char *key)
{
	int rd_idx = cpo_find_child(cpo, 0, "ResponseData");
	return cpo_get(cpo, cpo_find_child(cpo, rd_idx, key));
}

static int ccc_check_error(const cp_options *cpo, struct oc_text_buf *s)
{
	const cp_option *return_code, *error_code, *error_message, *error_msg = NULL;
	char *msg = NULL;
	int ret = 0;
	int rh_idx = cpo_find_child(cpo, 0, "ResponseHeader");
	error_code = get_from_rd(cpo, "error_code");
	return_code = cpo_get(cpo, cpo_find_child(cpo, rh_idx, "return_code"));

	if (atoi(return_code->value) != 600 || error_code) {
		error_message = get_from_rd(cpo, "error_message");
		if (error_message)
			msg = unscramble(error_message->value);
		else {
			error_msg = get_from_rd(cpo, "error_msg");
			if (error_msg)
				msg = error_msg->value;
		}
		buf_append(s, "%s (code %s)", msg ? msg : "", error_code ? error_code->value : return_code->value);
		if (buf_error(s))
			ret = -ENOMEM;
		else
			ret = -EIO;
	}
	if (!error_msg)
		free(msg);
	return ret;
}

static int do_ccc_client_hello(struct openconnect_info *vpninfo)
{
	static char pv[] = "protocol_version";
	int idx, idx2 = -1, ichild = -1;
	char *resp_buf = NULL;
	cp_options *cpo = NULL;
	const cp_option *opt = NULL;

	/* Open connection here to use gateway_addr */
	int result = connect_https_socket(vpninfo);
	if (result < 0)
		return result;
	char *gw = vpninfo->ip_info.gateway_addr;
	struct oc_text_buf *buf = buf_alloc();

	/* NOTE: client version fixed for now. */
	buf_append(buf, CCCclientRequestClientHello, 0, gw ? gw : "");
	if (!(result = buf_error(buf)))
		result = https_request_wrapper(vpninfo, buf, &resp_buf, 0);
	if (result > 0) {
		cpo = cpo_parse(resp_buf);
		if (cpo) {
			if ((result = ccc_check_error(cpo, buf))) {
				if (result != -ENOMEM)
					vpn_progress(vpninfo, PRG_ERR, _("Server returned error: '%s'\n"), buf->data);
			} else {
				/* Extract usefull info */

				opt = get_from_rd(cpo, pv);
				idx = cpo_get_index(cpo, opt);
				opt = cpo_get(cpo, cpo_find_child(cpo, idx, pv));
				vpn_progress(vpninfo, PRG_DEBUG, _("CheckPoint server protocol_version is %s\n"), opt->value);

				opt = get_from_rd(cpo, "connectivity_info");
				idx = cpo_get_index(cpo, opt);
				while (cpo_elem_iter(cpo, idx, &ichild)) {
					opt = cpo_get(cpo, ichild);
					if (!opt->key)
						continue;
					if (!strcmp(opt->key, "connect_with_certificate_url")) {
						if (strcmp(opt->value, "/clients/cert/"))
							vpn_progress(vpninfo, PRG_DEBUG, _("Non-standard connect_with_certificate_url: %s\n"), opt->value);
						/* XX: If we're using a client cert, subsequent requests need to use this endpoint */
						if (vpninfo->certinfo[0].cert) {
							vpninfo->redirect_url = strdup(opt->value);
							handle_redirect(vpninfo); /* FIXME: check errors */
						}
					} else if (!strcmp(opt->key, "cookie_name")) {
						/* XX: it's not clear that we ever need to use this value */
						if (strcmp(opt->value, "CPCVPN_SESSION_ID"))
							vpn_progress(vpninfo, PRG_DEBUG, _("Non-standard cookie_name: %s\n"), opt->value);
					} else if (!strcmp(opt->key, "supported_data_tunnel_protocols"))
						idx2 = cpo_get_index(cpo, opt);
				}
				if (idx2 > 0) {
					ichild = -1;
					while (cpo_elem_iter(cpo, idx2, &ichild)) {
						opt = cpo_get(cpo, ichild);
						vpn_progress(vpninfo, PRG_DEBUG, _("supported_data_tunnel_protocols: %s\n"), opt->value);
					}
				}
			}
		} else
			result = -EIO;
		cpo_free(cpo);
	}
	buf_free(buf);
	free(resp_buf);
	if (result < 0)
		vpninfo->quit_reason = "ClientHello request error";
	return result;
}

static int send_client_hello_command(struct openconnect_info *vpninfo)
{

	int ret, reconnect = vpninfo->ip_info.addr != NULL;
	char *request_body = NULL;
	int proto_ver = 1;
	int client_ver = 1;
	char *colon = strchr(vpninfo->cookie, ':'); /* slim_cookie:session_id */

	if (colon)
		*colon = '\0';
	ret = asprintf(&request_body, client_hello, client_ver, proto_ver,
		       (reconnect ? vpninfo->ip_info.addr : "0.0.0.0"),
		       (reconnect ? "true" : "false"), vpninfo->cookie);
	if (colon)
		*colon = ':';
	if (ret <= 0)
		return -ENOMEM;

	ret = snx_queue_command(vpninfo, request_body);
	free(request_body);
	return ret;
}

static struct oc_auth_form *get_user_creds(struct openconnect_info *vpninfo)
{
	int ret;

	struct oc_auth_form *form = calloc(1, sizeof(*form));
	if (!form) {
	nomem:
		free_auth_form(form);
		return NULL;
	}

	struct oc_form_opt *opt = form->opts = calloc(1, sizeof(*opt));
	if (!opt)
		goto nomem;
	opt->name = strdup("username");
	opt->label = strdup(_("Username (or Challenge Response):"));
	opt->type = OC_FORM_OPT_TEXT;

	struct oc_form_opt *opt2 = opt->next = calloc(1, sizeof(*opt));
	if (!opt2)
		goto nomem;
	opt2->name = strdup("password");
	opt2->label = strdup(_("Password, passcode, or PIN+tokencode (leave blank for Challenge Response):"));
	opt2->type = OC_FORM_OPT_PASSWORD;

	form->auth_id = strdup("cp_creds");
	form->message = strdup(_("Enter user credentials:"));

	ret = process_auth_form(vpninfo, form);
	if (OC_FORM_RESULT_OK != ret) {
		free_auth_form(form);
		return NULL;
	}

	return form;
}

static int handle_login_reply(const char*data, struct openconnect_info *vpninfo)
{
	int ret = -EINVAL;
	struct oc_text_buf *buf = buf_alloc();
	cp_options *cpo = cpo_parse(data);

	if (!cpo) {
		vpn_progress(vpninfo, PRG_ERR, _("Failed to parse login reply!\n"));
	} else {
		const struct cp_option *authn_status = get_from_rd(cpo, "authn_status");
		const struct cp_option *is_authenticated = get_from_rd(cpo, "is_authenticated");
		const struct cp_option *active_key = get_from_rd(cpo, "active_key");
		const struct cp_option *session_id = get_from_rd(cpo, "session_id");

		if ((ret = ccc_check_error(cpo, buf))) {
			const struct cp_option *ec = get_from_rd(cpo, "error_code");
			if (ret != -ENOMEM)
				vpn_progress(vpninfo, PRG_ERR, _("Received error during authentication: %s\n"), buf->data);
			if (!strcmp(ec->value, "101"))
				ret = -EPERM;
		} else {
			if (authn_status && !strcmp(authn_status->value, "done") &&
			    is_authenticated && !strcmp(is_authenticated->value, "true") &&
			    active_key && session_id) {
				char *slim_cookie = unscramble(active_key->value);

				if (!slim_cookie)
					ret = -ENOMEM;
				else {
					buf_append(buf, "%s:%s", slim_cookie, session_id->value);
					ret = buf_error(buf);
					if (!ret) {
						vpninfo->cookie = buf->data;
						buf->data = NULL;
					}
				}
				free(slim_cookie);
			} else
				vpn_progress(vpninfo, PRG_ERR, _("Unknown authentication error\n"));
		}
	}
	cpo_free(cpo);
	buf_free(buf);
	return ret;
}

static int do_get_cookie(struct openconnect_info *vpninfo)
{
	char *resp_buf = NULL;
	struct oc_text_buf *request_body = buf_alloc();
	int result = 0;


	if (vpninfo->certinfo[0].cert) {
		/* XX: we've already set urlpath to the server's connect_with_certificate_url */
		buf_append(request_body, CCCclientRequestCert);
	} else {
		struct oc_auth_form *form = get_user_creds(vpninfo);
		if (!form) {
			result = -EINVAL;
		} else {
			buf_append(request_body, CCCclientRequestUserPass);
			struct oc_form_opt *opt;
			for (opt = form->opts; opt; opt = opt->next) {
				buf_append(request_body, "        :%s (", opt->name);
				buf_append_scrambled(request_body, opt->_value);
				buf_append(request_body, ")\n");
			}
			buf_append(request_body, "    )\n)");
			free_auth_form(form);
			result = buf_error(request_body);
		}
	}

	if (!result) {
		result = https_request_wrapper(vpninfo, request_body, &resp_buf, 0);
		if (result > 0)
			result = handle_login_reply(resp_buf, vpninfo);
	}
	buf_free(request_body);
	FREE_PASS(resp_buf);
	return result;
}

static int gen_ranges(struct oc_ip_info *ip_info,
		      uint32_t ip_min, uint32_t ip_max)
{

	uint32_t ip = ip_min, imask, ip_low, ip_high;
	char abuf[INET_ADDRSTRLEN];

	while (ip <= ip_max) {
		struct oc_split_include *inc;
		/* make mask that covers current ip range, but does not exceed it. */
		uint32_t mask = 0;
		for (imask = 0; imask < 32; imask++) {
			uint32_t curbit = 1 << imask;
			mask |= curbit;
			ip_low = ip & (~mask);
			ip_high = ip_low | mask;
			if (ip_low < ip || ip_high > ip_max) {
				mask &= ~curbit;
				break;
			}
		}

		inc = malloc(sizeof (*inc));
		if (!inc)
			return -ENOMEM;

		char *s;
		uint32_t a = htonl(ip);
		if (asprintf(&s, "%s/%d", inet_ntop(AF_INET, &a, abuf, sizeof (abuf)), 32 - imask) <= 0) {
			free(inc);
			return -ENOMEM;
		}

		inc->route = s;
		inc->next = ip_info->split_includes;
		ip_info->split_includes = inc;
		ip += mask + 1;
	}
	return 0;
}

static int handle_ip_ranges(struct openconnect_info *vpninfo, struct oc_vpn_option *new_cstp_opts,
			    struct oc_ip_info *ip_info, const cp_options *cpo, int range_idx)
{
	int ret = 0, ichild = -1;
	const cp_option*from_elem, *to_elem;
	uint32_t from_ip_int, to_ip_int, gw_ip_int = strtoipv4(vpninfo->ip_info.gateway_addr);

	while (cpo_elem_iter(cpo, range_idx, &ichild)) {

		from_elem = cpo_get(cpo, cpo_find_child(cpo, ichild, "from"));
		to_elem = cpo_get(cpo, cpo_find_child(cpo, ichild, "to"));
		if (!from_elem || !to_elem)
			continue;

		from_ip_int = strtoipv4(from_elem->value);
		to_ip_int = strtoipv4(to_elem->value);

		if (from_ip_int == gw_ip_int)
			continue;

		vpn_progress(vpninfo, PRG_DEBUG, _("Received Legacy IP address range %s:%s\n"),
			     from_elem->value, to_elem->value);

		if ((ret = gen_ranges(ip_info, from_ip_int, to_ip_int)))
			break;
	}
	return ret;
}

static int handle_hello_reply(const char *data, struct openconnect_info *vpninfo)
{
	int ichild = -1;
	int i, ret = -EINVAL, idx, OM_idx, range_idx;
	const cp_option *opt;
	struct oc_vpn_option *new_cstp_opts = NULL;
	struct oc_ip_info new_ip_info = {};
	cp_options *cpo = cpo_parse(data);

	if (!cpo)
		return ret;
	opt = cpo->elems;

	/* Log version strings */
	opt = cpo_get(cpo, cpo_find_child(cpo, 0, "version"));
	vpn_progress(vpninfo, PRG_DEBUG, _("CheckPoint server version is %s\n"), opt->value);
	opt = cpo_get(cpo, cpo_find_child(cpo, 0, "protocol_version"));
	vpn_progress(vpninfo, PRG_DEBUG, _("CheckPoint server protocol_version is %s\n"), opt->value);

	/* Timeouts setup */
	idx = cpo_find_child(cpo, 0, "timeouts");
	opt = cpo_get(cpo, cpo_find_child(cpo, idx, "keepalive"));
	vpninfo->ssl_times.keepalive = MAX(10, (opt ? atoi(opt->value) : 0));
	opt = cpo_get(cpo, cpo_find_child(cpo, idx, "authentication"));
	vpninfo->auth_expiration = time(NULL) + (MAX(3600, (opt ? atoi(opt->value) : 0)));

	/* IP, NS, routing info */
	OM_idx = idx = cpo_find_child(cpo, 0, "OM");
	opt = cpo_get(cpo, cpo_find_child(cpo, idx, "ipaddr"));
	if (opt) {
		new_ip_info.addr = add_option_dup(&new_cstp_opts, "ipaddr", opt->value, -1);
		vpn_progress(vpninfo, PRG_DEBUG, _("Received internal Legacy IP address %s\n"), opt->value);
	}

	idx = cpo_find_child(cpo, OM_idx, "dns_servers");
	if (idx >= 0) {
		i = 0;
		while ((i < 3) && cpo_elem_iter(cpo, idx, &ichild)) {
			opt = cpo_get(cpo, ichild);
			vpn_progress(vpninfo, PRG_DEBUG, _("Received DNS server %s\n"), opt->value);
			new_ip_info.dns[i++] = add_option_dup(&new_cstp_opts, "DNS", opt->value, -1);
		}
	}

	opt = cpo_get(cpo, cpo_find_child(cpo, OM_idx, "dns_suffix"));
	if (opt && opt->value && strlen(opt->value))
		new_ip_info.domain = add_option_dup(&new_cstp_opts, "search", opt->value, -1);

	idx = cpo_find_child(cpo, OM_idx, "wins_servers");
	if (idx >= 0) {
		i = 0;
		ichild = -1;
		while ((i < 3) && cpo_elem_iter(cpo, idx, &ichild)) {
			opt = cpo_get(cpo, ichild);
			vpn_progress(vpninfo, PRG_DEBUG, _("Received WINS server %s\n"), opt->value);
			new_ip_info.nbns[i++] = add_option_dup(&new_cstp_opts, "WINS", opt->value, -1);
		}
	}
	/* Note: optional.subnet not used. */

	/* Sanity check */
	if (!new_ip_info.addr) {
		ret = -EINVAL;
		vpn_progress(vpninfo, PRG_ERR, _("Internal address not received\n"));
	} else {
		range_idx = cpo_find_child(cpo, 0, "range");
		if (range_idx >= 0)
			ret = handle_ip_ranges(vpninfo, new_cstp_opts, &new_ip_info, cpo, range_idx);
		if (!ret)
			ret = install_vpn_opts(vpninfo, new_cstp_opts, &new_ip_info);

		if (ret < 0) {
			/* new_ip_info is bad. Perhaps IP address changed? */
			free_optlist(new_cstp_opts);
			free_split_routes(&new_ip_info);
		} else {
			vpninfo->ssl_times.last_rekey = time(NULL);
			vpninfo->delay_tunnel_reason = NULL;
			/* Need to send disconnect packet after close */
			vpninfo->delay_close = DELAY_CLOSE_IMMEDIATE_CALLBACK;
		}
	}

	cpo_free(cpo);
	return ret;
}

static int snx_start_tunnel(struct openconnect_info *vpninfo)
{
	int result;
	openconnect_close_https(vpninfo, 0);

	/* Try to open connection and send hello */
	if (openconnect_open_https(vpninfo)) {
		vpninfo->quit_reason = "Failed to open HTTPS connection.";
		openconnect_close_https(vpninfo, 0);
		return -EIO;
	}

	result = send_client_hello_command(vpninfo);
	if (result < 0) {
		vpninfo->quit_reason = "Failed to send client_hello.";
		openconnect_close_https(vpninfo, 0);
		return -EIO;
	}

	/* XX: We'll (ab)use last_rekey by leaving it zero until hello_reply is received */
	vpninfo->ssl_times.last_rekey = 0;
	vpninfo->delay_tunnel_reason = awaiting_hello_reply;

	vpninfo->ssl_times.last_rx = vpninfo->ssl_times.last_tx = time(NULL);

	monitor_fd_new(vpninfo, ssl);
	monitor_read_fd(vpninfo, ssl);
	monitor_except_fd(vpninfo, ssl);
	return 0;
}

static int do_reconnect(struct openconnect_info *vpninfo)
{
	int result = ssl_reconnect(vpninfo);
	if (result)
		vpninfo->quit_reason = "Server reconnect failed";
	return result;
}

static int snx_handle_command(struct openconnect_info *vpninfo)
{
	char *data = (char *) vpninfo->cstp_pkt->data;
	int ret = 0;

	if (!strncmp(data, "(disconnect", 11)) {
		cp_options *cpo = cpo_parse(data);
		const cp_option *code = cpo_get(cpo, cpo_find_child(cpo, 0, "code"));
		const cp_option *msg = cpo_get(cpo, cpo_find_child(cpo, 0, "message"));
		if (code && !strncmp(code->value, "201", 3))
			ret = -EPERM;
		else
			ret = -EPIPE;
		vpn_progress(vpninfo, PRG_ERR, _("Server disconnect: %s (code %s)\n"),
			     msg ? msg->value : NULL, code ? code->value : NULL);
		cpo_free(cpo);
		vpninfo->quit_reason = "Disconnect on server request";
		return -EPIPE;
	} else if (!strncmp(data, "(hello_reply", 12)) {
		if (vpninfo->ssl_times.last_rekey)
			vpn_progress(vpninfo, PRG_ERR, _("WARNING: Repeated 'hello_reply' received. OpenConnect will fail if IP address(es) have changed.\nTo use updated routing, DNS or WINS options login again, please.\n"));
		ret = handle_hello_reply(data, vpninfo);
	} else if (!strncmp(data, "(hello_again", 12))
		vpn_progress(vpninfo, PRG_DEBUG, _("'hello_again' received, ignoring.\n"));
	else if (!strncmp(data, "(keepalive", 10))
		vpn_progress(vpninfo, PRG_DEBUG, _("'keepalive' received.\n"));
	else
		vpn_progress(vpninfo, PRG_INFO, _("Unknown server command %s, ignoring.\n"), data);

	FREE(vpninfo->cstp_pkt);
	return ret;
}

int cp_obtain_cookie(struct openconnect_info *vpninfo)
{
	int ret;

	/* XX: If the user has provided a non-empty urlpath, assume they know what they're
	 * doing and leave as-is.
	 */
	if (!vpninfo->urlpath) {
		vpninfo->urlpath = strdup("clients/");
		if (!vpninfo->urlpath)
			return -ENOMEM;
	}
	if ((ret = do_ccc_client_hello(vpninfo)) < 0)
		goto out;

	do {
		ret = do_get_cookie(vpninfo);
		if (ret < 0)
			break;
	} while (!vpninfo->cookie);

 out:
	return ret;
}

int cp_connect(struct openconnect_info *vpninfo)
{
	if (!vpninfo->cookie || !strlen(vpninfo->cookie))
		return 1;

	vpninfo->ip_info.mtu = 1500; /* Fixed 4 now */
	return snx_start_tunnel(vpninfo);
}

int cp_mainloop(struct openconnect_info *vpninfo, int *timeout, int readable)
{
	int ret = 0, result;

	if (vpninfo->ssl_fd == -1)
		return do_reconnect(vpninfo);

	if (vpninfo->ssl_times.last_rekey == 0)
		vpninfo->delay_tunnel_reason = awaiting_hello_reply;
	else if (vpninfo->got_cancel_cmd && vpninfo->cancel_type == OC_CMD_CANCEL)
		/* XX: we already set vpninfo->delay_close upon connection */
		snx_queue_command(vpninfo, disconnect);


	/* Service one incoming packet. */
	if (readable) {
		int ptype = -1;
		result = snx_receive(vpninfo, &ptype);
		if (result == -ENOMEM)
			return result;

		if (result != -EAGAIN) {
			if (result < 0)
				/* Try to reconnect on error */
				return do_reconnect(vpninfo);

			ret += result;

			/* FIXME: make this control flow / exception-handling saner */
			if (vpninfo->ssl_times.last_rekey == 0) {
				if (ptype != CMD) {
					vpn_progress(vpninfo, PRG_ERR, _("Unexpected packet received prior to hello_reply, ignoring\n"));
					dump_buf_hex(vpninfo, PRG_ERR, '<', (void *) &vpninfo->cstp_pkt->cpsnx.hdr, 8 + vpninfo->cstp_pkt->len);
					free(vpninfo->cstp_pkt);
					vpninfo->delay_tunnel_reason = awaiting_hello_reply;
					return 0;
				}
			}

			if (ptype == CMD) {
				result = snx_handle_command(vpninfo);
				if (result)
					return result;
			} else if (ptype == DATA) {
				queue_packet(&vpninfo->incoming_queue, vpninfo->cstp_pkt);
				vpninfo->cstp_pkt = NULL;
			} else
				vpn_progress(vpninfo, PRG_INFO, _("Unknown packet of type %d, ignoring.\n"), ptype);
		}
	}

	/* Service one outgoing packet. */

	if (!vpninfo->current_ssl_pkt) {
		struct pkt *this;
		if ((this = dequeue_packet(&vpninfo->tcp_control_queue)) != NULL) {
			store_be32(this->cpsnx.hdr + 4, CMD);
#ifdef INSECURE_DEBUGGING
			vpn_progress(vpninfo, PRG_DEBUG, _("Command packet outgoing\n%s\n"), this->data);
#else
			if (vpninfo->verbose >= PRG_DEBUG) {
				char *cmd_print = hide_auth_data(this->data);
				vpn_progress(vpninfo, PRG_DEBUG, _("Command outgoing:\n%s\n"), cmd_print);
				free(cmd_print);
			}
#endif
		} else if ((this = dequeue_packet(&vpninfo->outgoing_queue)) != NULL) {
			int tot_len = this->len + hdr_len;
			store_be32(this->cpsnx.hdr + 4, DATA);
			vpn_progress(vpninfo, PRG_TRACE, _("Data packet outgoing:\n"));
			dump_buf_hex(vpninfo, PRG_TRACE, '>', (void *) this->cpsnx.hdr, tot_len);
		}
		if (this) {
			store_be32(this->cpsnx.hdr, this->len);
			vpninfo->current_ssl_pkt = this;
		}
	} else
		unmonitor_write_fd(vpninfo, ssl);

	if (vpninfo->current_ssl_pkt) {
		vpninfo->ssl_times.last_tx = time(NULL);
		unmonitor_write_fd(vpninfo, ssl);

		result = ssl_nonblock_write(vpninfo, 0,
					 vpninfo->current_ssl_pkt->cpsnx.hdr,
					 vpninfo->current_ssl_pkt->len + hdr_len);
		ret += result;

		/* FIXME: need reconnect and ka_stalled_action handler here */
		if (result < 0) {
			return do_reconnect(vpninfo); /* FIXME: goto do_reconnect */
		} else if (!result) {
			switch (ka_stalled_action(&vpninfo->ssl_times, timeout)) {
			case KA_REKEY:
				break; /* FIXME: goto do_rekey; */
			case KA_DPD_DEAD:
				break; /* FIXME: goto peer_dead; */
			case KA_NONE:
				return ret;
			}
		}

		if (ret != vpninfo->current_ssl_pkt->len + hdr_len) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("SSL wrote too few bytes! Asked for %d, sent %d\n"),
				     vpninfo->current_ssl_pkt->len + hdr_len, ret);
			vpninfo->quit_reason = "Internal error";
			return 1;
		}

		/* Don't free the 'special' packets */
		if (vpninfo->current_ssl_pkt != &keepalive_pkt)
			free(vpninfo->current_ssl_pkt);

		vpninfo->current_ssl_pkt = NULL;
	}

	switch (keepalive_action(&vpninfo->ssl_times, timeout)) {
	case KA_DPD:
	case KA_KEEPALIVE:
		vpninfo->current_ssl_pkt = (struct pkt *)&keepalive_pkt;
		ret = 1; /* set work_done; FIXME: goto will make this much saner */
		break;
	case KA_DPD_DEAD:
		return do_reconnect(vpninfo);
	}
	return ret;
}

int cp_bye(struct openconnect_info *vpninfo, const char *reason)
{
	char *orig_path;
	int result;
	struct oc_text_buf *request_body = buf_alloc();
	char *data = NULL;
	char *colon = strchr(vpninfo->cookie, ':'); /* slim_cookie:session_id */

	if (colon) {
		orig_path = vpninfo->urlpath;
		vpninfo->urlpath = strdup(clients_str + 1);
		buf_append(request_body, CCCclientRequestSignout, colon + 1);
		if (vpninfo->urlpath && !buf_error(request_body)) {
			openconnect_close_https(vpninfo, 0);
			result = https_request_wrapper(vpninfo, request_body, &data, 0);
			free(vpninfo->urlpath);
			vpninfo->urlpath = orig_path;

			if (result < 0)
				vpn_progress(vpninfo, PRG_ERR, _("Logout failed.\n"));
			else
				vpn_progress(vpninfo, PRG_INFO, _("Logout successful.\n"));
		}
	}

	free(data);
	buf_free(request_body);
	return 0;
}
