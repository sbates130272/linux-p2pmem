/* Test the fsinfo() system call
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
#include <arpa/inet.h>

#ifndef __NR_fsinfo
#define __NR_fsinfo -1
#endif

static bool debug = 0;

static __attribute__((unused))
ssize_t fsinfo(int dfd, const char *filename, struct fsinfo_params *params,
	       void *buffer, size_t buf_size)
{
	return syscall(__NR_fsinfo, dfd, filename, params, buffer, buf_size);
}

#define FSINFO_STRING(X,Y)	 [FSINFO_ATTR_##X] = 0x0000
#define FSINFO_STRUCT(X,Y)	 [FSINFO_ATTR_##X] = sizeof(struct fsinfo_##Y)
#define FSINFO_STRING_N(X,Y)	 [FSINFO_ATTR_##X] = 0x4000
#define FSINFO_STRUCT_N(X,Y)	 [FSINFO_ATTR_##X] = 0x4000 | sizeof(struct fsinfo_##Y)
#define FSINFO_STRUCT_NM(X,Y)	 [FSINFO_ATTR_##X] = 0x8000 | sizeof(struct fsinfo_##Y)
#define FSINFO_STRING_NM(X,Y)	 [FSINFO_ATTR_##X] = 0x8000
static const __u16 fsinfo_buffer_sizes[FSINFO_ATTR__NR] = {
	FSINFO_STRUCT		(STATFS,		statfs),
	FSINFO_STRUCT		(FSINFO,		fsinfo),
	FSINFO_STRUCT		(IDS,			ids),
	FSINFO_STRUCT		(LIMITS,		limits),
	FSINFO_STRUCT		(CAPABILITIES,		capabilities),
	FSINFO_STRUCT		(SUPPORTS,		supports),
	FSINFO_STRUCT		(TIMESTAMP_INFO,	timestamp_info),
	FSINFO_STRING		(VOLUME_ID,		volume_id),
	FSINFO_STRUCT		(VOLUME_UUID,		volume_uuid),
	FSINFO_STRING		(VOLUME_NAME,		volume_name),
	FSINFO_STRING		(CELL_NAME,		cell_name),
	FSINFO_STRING		(DOMAIN_NAME,		domain_name),
	FSINFO_STRING_N		(SERVER_NAME,		server_name),
	FSINFO_STRUCT_NM	(SERVER_ADDRESS,	server_address),
	FSINFO_STRING_NM	(PARAMETER,		parameter),
	FSINFO_STRING_N		(SOURCE,		source),
	FSINFO_STRING		(NAME_ENCODING,		name_encoding),
	FSINFO_STRING		(NAME_CODEPAGE,		name_codepage),
	FSINFO_STRUCT		(IO_SIZE,		io_size),
	FSINFO_STRUCT		(PARAM_DESCRIPTION,	param_description),
	FSINFO_STRUCT_N		(PARAM_SPECIFICATION,	param_specification),
	FSINFO_STRUCT_N		(PARAM_NAME,		param_name),
	FSINFO_STRUCT_N		(PARAM_ENUM,		param_enum),
};

#define FSINFO_NAME(X,Y) [FSINFO_ATTR_##X] = #Y
static const char *fsinfo_attr_names[FSINFO_ATTR__NR] = {
	FSINFO_NAME		(STATFS,		statfs),
	FSINFO_NAME		(FSINFO,		fsinfo),
	FSINFO_NAME		(IDS,			ids),
	FSINFO_NAME		(LIMITS,		limits),
	FSINFO_NAME		(CAPABILITIES,		capabilities),
	FSINFO_NAME		(SUPPORTS,		supports),
	FSINFO_NAME		(TIMESTAMP_INFO,	timestamp_info),
	FSINFO_NAME		(VOLUME_ID,		volume_id),
	FSINFO_NAME		(VOLUME_UUID,		volume_uuid),
	FSINFO_NAME		(VOLUME_NAME,		volume_name),
	FSINFO_NAME		(CELL_NAME,		cell_name),
	FSINFO_NAME		(DOMAIN_NAME,		domain_name),
	FSINFO_NAME		(SERVER_NAME,		server_name),
	FSINFO_NAME		(SERVER_ADDRESS,	server_address),
	FSINFO_NAME		(PARAMETER,		parameter),
	FSINFO_NAME		(SOURCE,		source),
	FSINFO_NAME		(NAME_ENCODING,		name_encoding),
	FSINFO_NAME		(NAME_CODEPAGE,		name_codepage),
	FSINFO_NAME		(IO_SIZE,		io_size),
	FSINFO_NAME		(PARAM_DESCRIPTION,	param_description),
	FSINFO_NAME		(PARAM_SPECIFICATION,	param_specification),
	FSINFO_NAME		(PARAM_NAME,		param_name),
	FSINFO_NAME		(PARAM_ENUM,		param_enum),
};

union reply {
	char buffer[4096];
	struct fsinfo_statfs statfs;
	struct fsinfo_fsinfo fsinfo;
	struct fsinfo_ids ids;
	struct fsinfo_limits limits;
	struct fsinfo_supports supports;
	struct fsinfo_capabilities caps;
	struct fsinfo_timestamp_info timestamps;
	struct fsinfo_volume_uuid uuid;
	struct fsinfo_server_address srv_addr;
	struct fsinfo_io_size io_size;
};

static void dump_hex(unsigned int *data, int from, int to)
{
	unsigned offset, print_offset = 1, col = 0;

	from /= 4;
	to = (to + 3) / 4;

	for (offset = from; offset < to; offset++) {
		if (print_offset) {
			printf("%04x: ", offset * 8);
			print_offset = 0;
		}
		printf("%08x", data[offset]);
		col++;
		if ((col & 3) == 0) {
			printf("\n");
			print_offset = 1;
		} else {
			printf(" ");
		}
	}

	if (!print_offset)
		printf("\n");
}

static void dump_attr_STATFS(union reply *r, int size)
{
	struct fsinfo_statfs *f = &r->statfs;

	printf("\n");
	printf("\tblocks: n=%llu fr=%llu av=%llu\n",
	       (unsigned long long)f->f_blocks,
	       (unsigned long long)f->f_bfree,
	       (unsigned long long)f->f_bavail);

	printf("\tfiles : n=%llu fr=%llu av=%llu\n",
	       (unsigned long long)f->f_files,
	       (unsigned long long)f->f_ffree,
	       (unsigned long long)f->f_favail);
	printf("\tbsize : %u\n", f->f_bsize);
	printf("\tfrsize: %u\n", f->f_frsize);
}

static void dump_attr_FSINFO(union reply *r, int size)
{
	struct fsinfo_fsinfo *f = &r->fsinfo;

	printf("max_attr=%u max_cap=%u\n", f->max_attr, f->max_cap);
}

static void dump_attr_IDS(union reply *r, int size)
{
	struct fsinfo_ids *f = &r->ids;

	printf("\n");
	printf("\tdev   : %02x:%02x\n", f->f_dev_major, f->f_dev_minor);
	printf("\tfs    : type=%x name=%s\n", f->f_fstype, f->f_fs_name);
	printf("\tflags : %llx\n", (unsigned long long)f->f_flags);
	printf("\tfsid  : %llx\n", (unsigned long long)f->f_fsid);
}

static void dump_attr_LIMITS(union reply *r, int size)
{
	struct fsinfo_limits *f = &r->limits;

	printf("\n");
	printf("\tmax file size: %llx\n",
	       (unsigned long long)f->max_file_size);
	printf("\tmax ids      : u=%llx g=%llx p=%llx\n",
	       (unsigned long long)f->max_uid,
	       (unsigned long long)f->max_gid,
	       (unsigned long long)f->max_projid);
	printf("\tmax dev      : maj=%x min=%x\n",
	       f->max_dev_major, f->max_dev_minor);
	printf("\tmax links    : %x\n", f->max_hard_links);
	printf("\tmax xattr    : n=%x b=%x\n",
	       f->max_xattr_name_len, f->max_xattr_body_len);
	printf("\tmax len      : file=%x sym=%x\n",
	       f->max_filename_len, f->max_symlink_len);
}

static void dump_attr_SUPPORTS(union reply *r, int size)
{
	struct fsinfo_supports *f = &r->supports;

	printf("\n");
	printf("\tstx_attr=%llx\n", (unsigned long long)f->stx_attributes);
	printf("\tstx_mask=%x\n", f->stx_mask);
	printf("\tioc_flags=%x\n", f->ioc_flags);
	printf("\twin_fattrs=%x\n", f->win_file_attrs);
}

#define FSINFO_CAP_NAME(C) [FSINFO_CAP_##C] = #C
static const char *fsinfo_cap_names[FSINFO_CAP__NR] = {
	FSINFO_CAP_NAME(IS_KERNEL_FS),
	FSINFO_CAP_NAME(IS_BLOCK_FS),
	FSINFO_CAP_NAME(IS_FLASH_FS),
	FSINFO_CAP_NAME(IS_NETWORK_FS),
	FSINFO_CAP_NAME(IS_AUTOMOUNTER_FS),
	FSINFO_CAP_NAME(AUTOMOUNTS),
	FSINFO_CAP_NAME(ADV_LOCKS),
	FSINFO_CAP_NAME(MAND_LOCKS),
	FSINFO_CAP_NAME(LEASES),
	FSINFO_CAP_NAME(UIDS),
	FSINFO_CAP_NAME(GIDS),
	FSINFO_CAP_NAME(PROJIDS),
	FSINFO_CAP_NAME(ID_NAMES),
	FSINFO_CAP_NAME(ID_GUIDS),
	FSINFO_CAP_NAME(WINDOWS_ATTRS),
	FSINFO_CAP_NAME(USER_QUOTAS),
	FSINFO_CAP_NAME(GROUP_QUOTAS),
	FSINFO_CAP_NAME(PROJECT_QUOTAS),
	FSINFO_CAP_NAME(XATTRS),
	FSINFO_CAP_NAME(JOURNAL),
	FSINFO_CAP_NAME(DATA_IS_JOURNALLED),
	FSINFO_CAP_NAME(O_SYNC),
	FSINFO_CAP_NAME(O_DIRECT),
	FSINFO_CAP_NAME(VOLUME_ID),
	FSINFO_CAP_NAME(VOLUME_UUID),
	FSINFO_CAP_NAME(VOLUME_NAME),
	FSINFO_CAP_NAME(VOLUME_FSID),
	FSINFO_CAP_NAME(CELL_NAME),
	FSINFO_CAP_NAME(DOMAIN_NAME),
	FSINFO_CAP_NAME(REALM_NAME),
	FSINFO_CAP_NAME(IVER_ALL_CHANGE),
	FSINFO_CAP_NAME(IVER_DATA_CHANGE),
	FSINFO_CAP_NAME(IVER_MONO_INCR),
	FSINFO_CAP_NAME(SYMLINKS),
	FSINFO_CAP_NAME(HARD_LINKS),
	FSINFO_CAP_NAME(HARD_LINKS_1DIR),
	FSINFO_CAP_NAME(DEVICE_FILES),
	FSINFO_CAP_NAME(UNIX_SPECIALS),
	FSINFO_CAP_NAME(RESOURCE_FORKS),
	FSINFO_CAP_NAME(NAME_CASE_INDEP),
	FSINFO_CAP_NAME(NAME_NON_UTF8),
	FSINFO_CAP_NAME(NAME_HAS_CODEPAGE),
	FSINFO_CAP_NAME(SPARSE),
	FSINFO_CAP_NAME(NOT_PERSISTENT),
	FSINFO_CAP_NAME(NO_UNIX_MODE),
	FSINFO_CAP_NAME(HAS_ATIME),
	FSINFO_CAP_NAME(HAS_BTIME),
	FSINFO_CAP_NAME(HAS_CTIME),
	FSINFO_CAP_NAME(HAS_MTIME),
};

static void dump_attr_CAPABILITIES(union reply *r, int size)
{
	struct fsinfo_capabilities *f = &r->caps;
	int i;

	for (i = 0; i < sizeof(f->capabilities); i++)
		printf("%02x", f->capabilities[i]);
	printf("\n");
	for (i = 0; i < FSINFO_CAP__NR; i++)
		if (f->capabilities[i / 8] & (1 << (i % 8)))
			printf("\t- %s\n", fsinfo_cap_names[i]);
}

static void dump_attr_TIMESTAMP_INFO(union reply *r, int size)
{
	struct fsinfo_timestamp_info *f = &r->timestamps;

	printf("range=%llx-%llx\n",
	       (unsigned long long)f->minimum_timestamp,
	       (unsigned long long)f->maximum_timestamp);

#define print_time(G) \
	printf("\t"#G"time : gran=%gs\n",			\
	       (f->G##time_gran_mantissa *		\
		pow(10., f->G##time_gran_exponent)))
	print_time(a);
	print_time(b);
	print_time(c);
	print_time(m);
}

static void dump_attr_VOLUME_UUID(union reply *r, int size)
{
	struct fsinfo_volume_uuid *f = &r->uuid;

	printf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x"
	       "-%02x%02x%02x%02x%02x%02x\n",
	       f->uuid[ 0], f->uuid[ 1],
	       f->uuid[ 2], f->uuid[ 3],
	       f->uuid[ 4], f->uuid[ 5],
	       f->uuid[ 6], f->uuid[ 7],
	       f->uuid[ 8], f->uuid[ 9],
	       f->uuid[10], f->uuid[11],
	       f->uuid[12], f->uuid[13],
	       f->uuid[14], f->uuid[15]);
}

static void dump_attr_SERVER_ADDRESS(union reply *r, int size)
{
	struct fsinfo_server_address *f = &r->srv_addr;
	struct sockaddr_in6 *sin6;
	struct sockaddr_in *sin;
	char buf[1024];

	switch (f->address.ss_family) {
	case AF_INET:
		sin = (struct sockaddr_in *)&f->address;
		if (!inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf)))
			break;
		printf("IPv4: %s\n", buf);
		return;
	case AF_INET6:
		sin6 = (struct sockaddr_in6 *)&f->address;
		if (!inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf)))
			break;
		printf("IPv6: %s\n", buf);
		return;
	}

	printf("family=%u\n", f->address.ss_family);
}

static void dump_attr_IO_SIZE(union reply *r, int size)
{
	struct fsinfo_io_size *f = &r->io_size;

	printf("dio_size=%u\n", f->dio_size_gran);
}

/*
 *
 */
typedef void (*dumper_t)(union reply *r, int size);

#define FSINFO_DUMPER(N) [FSINFO_ATTR_##N] = dump_attr_##N
static const dumper_t fsinfo_attr_dumper[FSINFO_ATTR__NR] = {
	FSINFO_DUMPER(STATFS),
	FSINFO_DUMPER(FSINFO),
	FSINFO_DUMPER(IDS),
	FSINFO_DUMPER(LIMITS),
	FSINFO_DUMPER(SUPPORTS),
	FSINFO_DUMPER(CAPABILITIES),
	FSINFO_DUMPER(TIMESTAMP_INFO),
	FSINFO_DUMPER(VOLUME_UUID),
	FSINFO_DUMPER(SERVER_ADDRESS),
	FSINFO_DUMPER(IO_SIZE),
};

static void dump_fsinfo(enum fsinfo_attribute attr, __u8 about,
			union reply *r, int size)
{
	dumper_t dumper = fsinfo_attr_dumper[attr];
	unsigned int len;

	if (!dumper) {
		printf("<no dumper>\n");
		return;
	}

	len = about & 0x3fff;
	if (size < len) {
		printf("<short data %u/%u>\n", size, len);
		return;
	}

	dumper(r, size);
}

/*
 * Try one subinstance of an attribute.
 */
static int try_one(const char *file, struct fsinfo_params *params, bool raw)
{
	union reply r;
	char *p;
	int ret;
	__u16 about;

	memset(&r.buffer, 0xbd, sizeof(r.buffer));

	errno = 0;
	ret = fsinfo(AT_FDCWD, file, params, r.buffer, sizeof(r.buffer));
	if (params->request >= FSINFO_ATTR__NR) {
		if (ret == -1 && errno == EOPNOTSUPP)
			exit(0);
		fprintf(stderr, "Unexpected error for too-large command %u: %m\n",
			params->request);
		exit(1);
	}

	if (debug)
		printf("fsinfo(%s,%s,%u,%u) = %d: %m\n",
		       file, fsinfo_attr_names[params->request],
		       params->Nth, params->Mth, ret);

	about = fsinfo_buffer_sizes[params->request];
	if (ret == -1) {
		if (errno == ENODATA) {
			switch (about & 0xc000) {
			case 0x0000:
				if (params->Nth == 0 && params->Mth == 0) {
					fprintf(stderr,
						"Unexpected ENODATA1 (%u[%u][%u])\n",
						params->request, params->Nth, params->Mth);
					exit(1);
				}
				break;
			case 0x4000:
				if (params->Nth == 0 && params->Mth == 0) {
					fprintf(stderr,
						"Unexpected ENODATA2 (%u[%u][%u])\n",
						params->request, params->Nth, params->Mth);
					exit(1);
				}
				break;
			}
			return (params->Mth == 0) ? 2 : 1;
		}
		if (errno == EOPNOTSUPP) {
			if (params->Nth > 0 || params->Mth > 0) {
				fprintf(stderr,
					"Should return -ENODATA (%u[%u][%u])\n",
					params->request, params->Nth, params->Mth);
				exit(1);
			}
			//printf("\e[33m%s\e[m: <not supported>\n",
			//       fsinfo_attr_names[attr]);
			return 2;
		}
		perror(file);
		exit(1);
	}

	if (raw) {
		if (ret > 4096)
			ret = 4096;
		dump_hex((unsigned int *)&r.buffer, 0, ret);
		return 0;
	}

	switch (params->request) {
	case FSINFO_ATTR_PARAMETER:
		if (ret == 0)
			return 0;
	}

	switch (about & 0xc000) {
	case 0x0000:
		printf("\e[33m%s\e[m: ",
		       fsinfo_attr_names[params->request]);
		break;
	case 0x4000:
		printf("\e[33m%s[%u]\e[m: ",
		       fsinfo_attr_names[params->request],
		       params->Nth);
		break;
	case 0x8000:
		printf("\e[33m%s[%u][%u]\e[m: ",
		       fsinfo_attr_names[params->request],
		       params->Nth, params->Mth);
		break;
	}

	switch (about) {
		/* Struct */
	case 0x0001 ... 0x3fff:
	case 0x4001 ... 0x7fff:
	case 0x8001 ... 0xbfff:
		dump_fsinfo(params->request, about, &r, ret);
		return 0;

		/* String */
	case 0x0000:
	case 0x4000:
	case 0x8000:
		if (ret >= 4096) {
			ret = 4096;
			r.buffer[4092] = '.';
			r.buffer[4093] = '.';
			r.buffer[4094] = '.';
			r.buffer[4095] = 0;
		} else {
			r.buffer[ret] = 0;
		}
		for (p = r.buffer; *p; p++) {
			if (!isprint(*p)) {
				printf("<non-printable>\n");
				continue;
			}
		}
		printf("%s\n", r.buffer);
		return 0;

	default:
		fprintf(stderr, "Fishy about %u %02x\n", params->request, about);
		exit(1);
	}
}

/*
 *
 */
int main(int argc, char **argv)
{
	struct fsinfo_params params = {
		.at_flags = AT_SYMLINK_NOFOLLOW,
	};
	unsigned int attr;
	int raw = 0, opt, Nth, Mth;

	while ((opt = getopt(argc, argv, "adlr"))) {
		switch (opt) {
		case 'a':
			params.at_flags |= AT_NO_AUTOMOUNT;
			continue;
		case 'd':
			debug = true;
			continue;
		case 'l':
			params.at_flags &= ~AT_SYMLINK_NOFOLLOW;
			continue;
		case 'r':
			raw = 1;
			continue;
		}
		break;
	}

	argc -= optind;
	argv += optind;

	if (argc != 1) {
		printf("Format: test-fsinfo [-alr] <file>\n");
		exit(2);
	}

	for (attr = 0; attr <= FSINFO_ATTR__NR; attr++) {
		switch (attr) {
		case FSINFO_ATTR_PARAM_DESCRIPTION:
		case FSINFO_ATTR_PARAM_SPECIFICATION:
		case FSINFO_ATTR_PARAM_NAME:
		case FSINFO_ATTR_PARAM_ENUM:
			/* See test-fs-query.c instead */
			continue;
		}

		Nth = 0;
		do {
			Mth = 0;
			do {
				params.request = attr;
				params.Nth = Nth;
				params.Mth = Mth;

				switch (try_one(argv[0], &params, raw)) {
				case 0:
					continue;
				case 1:
					goto done_M;
				case 2:
					goto done_N;
				}
			} while (++Mth < 100);

		done_M:
			if (Mth >= 100) {
				fprintf(stderr, "Fishy: Mth == %u\n", Mth);
				break;
			}

		} while (++Nth < 100);

	done_N:
		if (Nth >= 100) {
			fprintf(stderr, "Fishy: Nth == %u\n", Nth);
			break;
		}
	}

	return 0;
}
