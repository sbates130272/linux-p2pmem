/* Test using the fsinfo() system call to query mount parameters.
 *
 * Copyright (C) 2018 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#define _GNU_SOURCE
#define _ATFILE_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <math.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <linux/fsinfo.h>
#include <linux/socket.h>
#include <sys/stat.h>

#ifndef __NR_fsopen
#define __NR_fsopen -1
#endif
#ifndef __NR_fsinfo
#define __NR_fsinfo -1
#endif

static int fsopen(const char *fs_name, unsigned int flags)
{
	return syscall(__NR_fsopen, fs_name, flags);
}

static ssize_t fsinfo(int dfd, const char *filename, struct fsinfo_params *params,
		      void *buffer, size_t buf_size)
{
	return syscall(__NR_fsinfo, dfd, filename, params, buffer, buf_size);
}

static const char *param_types[NR__FSINFO_PARAM_SPEC] = {
	[FSINFO_PARAM_SPEC_NOT_DEFINED]		= "?undef",
	[FSINFO_PARAM_SPEC_TAKES_NO_VALUE]	= "no-val",
	[FSINFO_PARAM_SPEC_IS_BOOL]		= "bool",
	[FSINFO_PARAM_SPEC_IS_U32]		= "u32",
	[FSINFO_PARAM_SPEC_IS_U32_OCTAL]	= "octal",
	[FSINFO_PARAM_SPEC_IS_U32_HEX]		= "hex",
	[FSINFO_PARAM_SPEC_IS_S32]		= "s32",
	[FSINFO_PARAM_SPEC_IS_U64]		= "u64",
	[FSINFO_PARAM_SPEC_IS_ENUM]		= "enum",
	[FSINFO_PARAM_SPEC_IS_STRING]		= "string",
	[FSINFO_PARAM_SPEC_IS_BLOB]		= "binary",
	[FSINFO_PARAM_SPEC_IS_BLOCKDEV]		= "blockdev",
	[FSINFO_PARAM_SPEC_IS_PATH]		= "path",
	[FSINFO_PARAM_SPEC_IS_FD]		= "fd",
};

/*
 *
 */
int main(int argc, char **argv)
{
	struct fsinfo_param_description desc;
	struct fsinfo_param_specification spec;
	struct fsinfo_param_name name;
	struct fsinfo_param_enum enum_name;

	struct fsinfo_params params = {
		.at_flags = AT_SYMLINK_NOFOLLOW,
	};
	int fd;

	if (argc != 2) {
		printf("Format: test-fs-query <fs_name>\n");
		exit(2);
	}

	fd = fsopen(argv[1], 0);
	if (fd == -1) {
		perror(argv[1]);
		exit(1);
	}

	params.request = FSINFO_ATTR_PARAM_DESCRIPTION;
	if (fsinfo(fd, NULL, &params, &desc, sizeof(desc)) == -1) {
		perror("fsinfo/desc");
		exit(1);
	}

	printf("Filesystem %s has %u parameters\n", argv[1], desc.nr_params);

	params.request = FSINFO_ATTR_PARAM_SPECIFICATION;
	for (params.Nth = 0; params.Nth < desc.nr_params; params.Nth++) {
		if (fsinfo(fd, NULL, &params, &spec, sizeof(spec)) == -1) {
			if (errno == ENODATA)
				break;
			perror("fsinfo/spec");
			exit(1);
		}
		printf("- PARAM[%3u] type=%u(%s)%s%s%s%s\n",
		       params.Nth,
		       spec.type,
		       spec.type < NR__FSINFO_PARAM_SPEC ? param_types[spec.type] : "?type",
		       spec.flags & FSINFO_PARAM_SPEC_VALUE_IS_OPTIONAL ? " -opt" : "",
		       spec.flags & FSINFO_PARAM_SPEC_PREFIX_NO_IS_NEG ? " -neg-no" : "",
		       spec.flags & FSINFO_PARAM_SPEC_EMPTY_STRING_IS_NEG ? " -neg-empty" : "",
		       spec.flags & FSINFO_PARAM_SPEC_DEPRECATED ? " -dep" : "");
	}

	printf("Filesystem has %u parameter names\n", desc.nr_names);

	params.request = FSINFO_ATTR_PARAM_NAME;
	for (params.Nth = 0; params.Nth < desc.nr_names; params.Nth++) {
		if (fsinfo(fd, NULL, &params, &name, sizeof(name)) == -1) {
			if (errno == ENODATA)
				break;
			perror("fsinfo/name");
			exit(1);
		}
		printf("- NAME[%3u] %s -> %u\n",
		       params.Nth, name.name, name.param_index);
	}

	printf("Filesystem has %u enumeration values\n", desc.nr_enum_names);

	params.request = FSINFO_ATTR_PARAM_ENUM;
	for (params.Nth = 0; params.Nth < desc.nr_enum_names; params.Nth++) {
		if (fsinfo(fd, NULL, &params, &enum_name, sizeof(enum_name)) == -1) {
			if (errno == ENODATA)
				break;
			perror("fsinfo/enum");
			exit(1);
		}
		printf("- ENUM[%3u] %3u.%s\n",
		       params.Nth, enum_name.param_index, enum_name.name);
	}
	return 0;
}
