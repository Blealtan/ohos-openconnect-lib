/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2023 Jan-Michael Brummer <jan-michael.brummer1@volkswagen.de>
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifndef _WIN32
#include <pwd.h>
#endif

#define DATA_FILE_NAME "globalprotect.dat"

static char *get_user_cache_dir(void)
{
	char *cache_dir;
	int cache_dir_len;
#ifndef _WIN32
	struct passwd *pw = getpwuid(getuid());
	char *home = strdup(pw->pw_dir);
#else
	/* TODO: Add WIN32 implementation */
	char *home = strdup("");
#endif

	/* Ensure that the openconnect cache dir exists */
	cache_dir_len = strlen(home) + strlen("/.cache/openconnect/") + 1;
	cache_dir = malloc(cache_dir_len);
	snprintf(cache_dir, cache_dir_len, "%s/.cache/openconnect/", home);
	free(home);

#ifndef _WIN32
	mkdir(cache_dir, 0700);
#else
	mkdir(cache_dir);
#endif

	return cache_dir;
}

int main(int argc, char **argv)
{
	FILE *fp;
	char *callback_data;
	char *oc_cache_dir;
	char *data_file;
	int data_file_len;
	int ret = 0;

	if (argc < 2)
		return -1;

	callback_data = argv[1];

	oc_cache_dir = get_user_cache_dir();

	data_file_len = strlen (oc_cache_dir) + strlen (DATA_FILE_NAME) + 2;
	data_file = malloc (data_file_len);
	strcpy(data_file, oc_cache_dir);
	strcat(data_file, "/");
	strcat(data_file, DATA_FILE_NAME);

	fp = fopen(data_file, "w");
	if (fp) {
		/* callback_data format:
		 * globalprotectcallback:DATA
		 *
		 * DATA:
		 * - Using CAS: cas-as=1&un=<USER>&token=<TOKEN>
		 * - Without CAS: <TOKEN>
		 *
		 * As we just want the data, we skip the prefix
		 */
		fwrite(callback_data + strlen("globalprotectcallback:"),
		       strlen(callback_data) - strlen("globalprotectcallback:"),
		       1,
		       fp);
		fclose (fp);
		ret = 0;
	}

	free(data_file);
	free(oc_cache_dir);

	return ret;
}
