/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2015 Intel Corporation.
 *
 * Author: David Woodhouse <dwmw2@infradead.org>
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

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
/* must precede iphlpapi.h, per https://docs.microsoft.com/en-us/windows/win32/api/iptypes/ns-iptypes-ip_adapter_addresses_lh */
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <netioapi.h>

#include <errno.h>
#include <stdio.h>

/* TAP driver 9.21.2 we download from the OpenVPN download page */
#define TAP_COMPONENT_ID "tap0901"
/* TAP driver bundled with OpenVPN */
#define TAP_OVPNCONNECT_COMPONENT_ID "tap_ovpnconnect"

#define NETDEV_GUID "{4D36E972-E325-11CE-BFC1-08002BE10318}"
#define CONTROL_KEY "SYSTEM\\CurrentControlSet\\Control\\"

#define ADAPTERS_KEY CONTROL_KEY "Class\\" NETDEV_GUID
#define CONNECTIONS_KEY CONTROL_KEY "Network\\" NETDEV_GUID

#define ADAPTER_TUNTAP 0
#define ADAPTER_WINTUN 1

typedef intptr_t (tap_callback)(struct openconnect_info *vpninfo, int type, char *idx, wchar_t *name);

#define SEARCH_CONTINUE	0
#define SEARCH_DONE	1

static intptr_t search_taps(struct openconnect_info *vpninfo, tap_callback *cb)
{
	LONG status;
	HKEY adapters_key, hkey;
	DWORD len, type;
	int adapter_type;
	char buf[40];
	wchar_t name[MAX_ADAPTER_NAME];
	char keyname[strlen(CONNECTIONS_KEY) + sizeof(buf) + 1 + strlen("\\Connection")];
	int i = 0;
	intptr_t ret = OPEN_TUN_SOFTFAIL;

	status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, ADAPTERS_KEY, 0,
			       KEY_READ, &adapters_key);
	if (status) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error accessing registry key for network adapters\n"));
		return -EIO;
	}
	while (ret == OPEN_TUN_SOFTFAIL) {
		len = sizeof(buf);
		status = RegEnumKeyExA(adapters_key, i++, buf, &len,
				       NULL, NULL, NULL, NULL);
		if (status) {
			if (status != ERROR_NO_MORE_ITEMS)
				ret = OPEN_TUN_HARDFAIL;
			break;
		}

		snprintf(keyname, sizeof(keyname), "%s\\%s",
			 ADAPTERS_KEY, buf);

		status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, keyname, 0,
				       KEY_QUERY_VALUE, &hkey);
		if (status)
			continue;

		len = sizeof(buf);
		status = RegQueryValueExA(hkey, "ComponentId", NULL, &type,
					  (unsigned char *)buf, &len);
		if (status || type != REG_SZ) {
			if (status == ERROR_FILE_NOT_FOUND) {
				vpn_progress(vpninfo, PRG_TRACE,
					_("Cannot read registry key %s\\%s: value not found\n"),
					keyname, "ComponentId");
			}
			else if (type != REG_SZ) {
				vpn_progress(vpninfo, PRG_TRACE,
					_("Cannot read registry key %s\\%s: value is not a string (%ld)\n"),
					keyname, "ComponentId", type);
			}
			else {
				vpn_progress(vpninfo, PRG_TRACE,
					_("Cannot read registry key %s\\%s or is not string: %s (%ld)\n"),
					keyname, "ComponentId", openconnect__win32_strerror(status), status);
			}
			RegCloseKey(hkey);
			continue;
		}
		if (!stricmp(buf, TAP_COMPONENT_ID) || !stricmp(buf, "root\\" TAP_COMPONENT_ID) ||
		    !stricmp(buf, TAP_OVPNCONNECT_COMPONENT_ID) ||
		    !stricmp(buf, "root\\" TAP_OVPNCONNECT_COMPONENT_ID))
			adapter_type = ADAPTER_TUNTAP;
		else if (!stricmp(buf, "Wintun"))
			adapter_type = ADAPTER_WINTUN;
		else {
			vpn_progress(vpninfo, PRG_TRACE, _("%s\\ComponentId is unknown '%s'\n"),
				     keyname, buf);
			RegCloseKey(hkey);
			continue;
		}

		vpn_progress(vpninfo, PRG_TRACE, _("Found %s at %s\n"),
			     buf, keyname);

		len = sizeof(buf);
		status = RegQueryValueExA(hkey, "NetCfgInstanceId", NULL,
					  &type, (unsigned char *)buf, &len);
		RegCloseKey(hkey);
		if (status || type != REG_SZ)
			continue;

		snprintf(keyname, sizeof(keyname), "%s\\%s\\Connection",
			 CONNECTIONS_KEY, buf);

		status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, keyname, 0,
				       KEY_QUERY_VALUE, &hkey);
		if (status) {
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Cannot open registry key %s\n"),
				     keyname);
			continue;
		}

		len = sizeof(name);
		status = RegQueryValueExW(hkey, L"Name", NULL, &type,
					 (unsigned char *)name, &len);
		RegCloseKey(hkey);
		if (status || type != REG_SZ) {
			if (status == ERROR_FILE_NOT_FOUND) {
				vpn_progress(vpninfo, PRG_INFO,
					_("Cannot read registry key %s\\%s: value not found\n"),
					keyname, "Name");
			}
			else if (status == ERROR_MORE_DATA) {
				vpn_progress(vpninfo, PRG_INFO,
					_("Cannot read registry key %s\\%s: character buffer too small: %llu chars required\n"),
					keyname, "Name", (long long unsigned int)(len / sizeof(wchar_t)));
			}
			else if (type != REG_SZ) {
				vpn_progress(vpninfo, PRG_INFO,
					_("Cannot read registry key %s\\%s: value is not a string (%ld)\n"),
					keyname, "Name", type);
			}
			else {
				vpn_progress(vpninfo, PRG_INFO,
					_("Cannot read registry key %s\\%s: %s (%ld)\n"),
					keyname, "Name", openconnect__win32_strerror(status), status);
			}
			continue;
		}

		ret = cb(vpninfo, adapter_type, buf, name);
	}

	RegCloseKey(adapters_key);

	return ret;
}
