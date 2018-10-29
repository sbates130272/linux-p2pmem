/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* fsinfo() definitions.
 *
 * Copyright (C) 2018 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */
#ifndef _UAPI_LINUX_FSINFO_H
#define _UAPI_LINUX_FSINFO_H

#include <linux/types.h>
#include <linux/socket.h>

/*
 * The filesystem attributes that can be requested.  Note that some attributes
 * may have multiple instances which can be switched in the parameter block.
 */
enum fsinfo_attribute {
	FSINFO_ATTR_STATFS		= 0,	/* statfs()-style state */
	FSINFO_ATTR_FSINFO		= 1,	/* Information about fsinfo() */
	FSINFO_ATTR_IDS			= 2,	/* Filesystem IDs */
	FSINFO_ATTR_LIMITS		= 3,	/* Filesystem limits */
	FSINFO_ATTR_SUPPORTS		= 4,	/* What's supported in statx, iocflags, ... */
	FSINFO_ATTR_CAPABILITIES	= 5,	/* Filesystem capabilities (bits) */
	FSINFO_ATTR_TIMESTAMP_INFO	= 6,	/* Inode timestamp info */
	FSINFO_ATTR_VOLUME_ID		= 7,	/* Volume ID (string) */
	FSINFO_ATTR_VOLUME_UUID		= 8,	/* Volume UUID (LE uuid) */
	FSINFO_ATTR_VOLUME_NAME		= 9,	/* Volume name (string) */
	FSINFO_ATTR_CELL_NAME		= 10,	/* Cell name (string) */
	FSINFO_ATTR_DOMAIN_NAME		= 11,	/* Domain name (string) */
	FSINFO_ATTR_SERVER_NAME		= 12,	/* Name of the Nth server */
	FSINFO_ATTR_SERVER_ADDRESS	= 13,	/* Mth address of the Nth server */
	FSINFO_ATTR_PARAMETER		= 14,	/* Nth mount parameter (string) */
	FSINFO_ATTR_SOURCE		= 15,	/* Nth mount source name (string) */
	FSINFO_ATTR_NAME_ENCODING	= 16,	/* Filename encoding (string) */
	FSINFO_ATTR_NAME_CODEPAGE	= 17,	/* Filename codepage (string) */
	FSINFO_ATTR_IO_SIZE		= 18,	/* Optimal I/O sizes */
	FSINFO_ATTR_PARAM_DESCRIPTION	= 19,	/* General fs parameter description */
	FSINFO_ATTR_PARAM_SPECIFICATION	= 20,	/* Nth parameter specification */
	FSINFO_ATTR_PARAM_NAME		= 21,	/* Nth name to param index */
	FSINFO_ATTR_PARAM_ENUM		= 22,	/* Nth enum-to-val */
	FSINFO_ATTR__NR
};

/*
 * Optional fsinfo() parameter structure.
 *
 * If this is not given, it is assumed that fsinfo_attr_statfs instance 0,0 is
 * desired.
 */
struct fsinfo_params {
	__u32	at_flags;	/* AT_SYMLINK_NOFOLLOW and similar flags */
	__u32	request;	/* What is being asking for (enum fsinfo_attribute) */
	__u32	Nth;		/* Instance of it (some may have multiple) */
	__u32	Mth;		/* Subinstance of Nth instance */
	__u32	__reserved[6];	/* Reserved params; all must be 0 */
};

/*
 * Information struct for fsinfo(fsinfo_attr_statfs).
 * - This gives extended filesystem information.
 */
struct fsinfo_statfs {
	__u64	f_blocks;	/* Total number of blocks in fs */
	__u64	f_bfree;	/* Total number of free blocks */
	__u64	f_bavail;	/* Number of free blocks available to ordinary user */
	__u64	f_files;	/* Total number of file nodes in fs */
	__u64	f_ffree;	/* Number of free file nodes */
	__u64	f_favail;	/* Number of free file nodes available to ordinary user */
	__u32	f_bsize;	/* Optimal block size */
	__u32	f_frsize;	/* Fragment size */
};

/*
 * Information struct for fsinfo(fsinfo_attr_ids).
 *
 * List of basic identifiers as is normally found in statfs().
 */
struct fsinfo_ids {
	char	f_fs_name[15 + 1];
	__u64	f_flags;	/* Filesystem mount flags (MS_*) */
	__u64	f_fsid;		/* Short 64-bit Filesystem ID (as statfs) */
	__u64	f_sb_id;	/* Internal superblock ID for sbnotify()/mntnotify() */
	__u32	f_fstype;	/* Filesystem type from linux/magic.h [uncond] */
	__u32	f_dev_major;	/* As st_dev_* from struct statx [uncond] */
	__u32	f_dev_minor;
	__u32	__reserved[1];
};

/*
 * Information struct for fsinfo(fsinfo_attr_limits).
 *
 * List of supported filesystem limits.
 */
struct fsinfo_limits {
	__u64	max_file_size;			/* Maximum file size */
	__u64	max_uid;			/* Maximum UID supported */
	__u64	max_gid;			/* Maximum GID supported */
	__u64	max_projid;			/* Maximum project ID supported */
	__u32	max_dev_major;			/* Maximum device major representable */
	__u32	max_dev_minor;			/* Maximum device minor representable */
	__u32	max_hard_links;			/* Maximum number of hard links on a file */
	__u32	max_xattr_body_len;		/* Maximum xattr content length */
	__u32	max_xattr_name_len;		/* Maximum xattr name length */
	__u32	max_filename_len;		/* Maximum filename length */
	__u32	max_symlink_len;		/* Maximum symlink content length */
	__u32	__reserved[1];
};

/*
 * Information struct for fsinfo(fsinfo_attr_supports).
 *
 * What's supported in various masks, such as statx() attribute and mask bits
 * and IOC flags.
 */
struct fsinfo_supports {
	__u64	stx_attributes;		/* What statx::stx_attributes are supported */
	__u32	stx_mask;		/* What statx::stx_mask bits are supported */
	__u32	ioc_flags;		/* What FS_IOC_* flags are supported */
	__u32	win_file_attrs;		/* What DOS/Windows FILE_* attributes are supported */
	__u32	__reserved[1];
};

/*
 * Information struct for fsinfo(fsinfo_attr_capabilities).
 *
 * Bitmask indicating filesystem capabilities where renderable as single bits.
 */
enum fsinfo_capability {
	FSINFO_CAP_IS_KERNEL_FS		= 0,	/* fs is kernel-special filesystem */
	FSINFO_CAP_IS_BLOCK_FS		= 1,	/* fs is block-based filesystem */
	FSINFO_CAP_IS_FLASH_FS		= 2,	/* fs is flash filesystem */
	FSINFO_CAP_IS_NETWORK_FS	= 3,	/* fs is network filesystem */
	FSINFO_CAP_IS_AUTOMOUNTER_FS	= 4,	/* fs is automounter special filesystem */
	FSINFO_CAP_AUTOMOUNTS		= 5,	/* fs supports automounts */
	FSINFO_CAP_ADV_LOCKS		= 6,	/* fs supports advisory file locking */
	FSINFO_CAP_MAND_LOCKS		= 7,	/* fs supports mandatory file locking */
	FSINFO_CAP_LEASES		= 8,	/* fs supports file leases */
	FSINFO_CAP_UIDS			= 9,	/* fs supports numeric uids */
	FSINFO_CAP_GIDS			= 10,	/* fs supports numeric gids */
	FSINFO_CAP_PROJIDS		= 11,	/* fs supports numeric project ids */
	FSINFO_CAP_ID_NAMES		= 12,	/* fs supports user names */
	FSINFO_CAP_ID_GUIDS		= 13,	/* fs supports user guids */
	FSINFO_CAP_WINDOWS_ATTRS	= 14,	/* fs has windows attributes */
	FSINFO_CAP_USER_QUOTAS		= 15,	/* fs has per-user quotas */
	FSINFO_CAP_GROUP_QUOTAS		= 16,	/* fs has per-group quotas */
	FSINFO_CAP_PROJECT_QUOTAS	= 17,	/* fs has per-project quotas */
	FSINFO_CAP_XATTRS		= 18,	/* fs has xattrs */
	FSINFO_CAP_JOURNAL		= 19,	/* fs has a journal */
	FSINFO_CAP_DATA_IS_JOURNALLED	= 20,	/* fs is using data journalling */
	FSINFO_CAP_O_SYNC		= 21,	/* fs supports O_SYNC */
	FSINFO_CAP_O_DIRECT		= 22,	/* fs supports O_DIRECT */
	FSINFO_CAP_VOLUME_ID		= 23,	/* fs has a volume ID */
	FSINFO_CAP_VOLUME_UUID		= 24,	/* fs has a volume UUID */
	FSINFO_CAP_VOLUME_NAME		= 25,	/* fs has a volume name */
	FSINFO_CAP_VOLUME_FSID		= 26,	/* fs has a volume FSID */
	FSINFO_CAP_CELL_NAME		= 27,	/* fs has a cell name */
	FSINFO_CAP_DOMAIN_NAME		= 28,	/* fs has a domain name */
	FSINFO_CAP_REALM_NAME		= 29,	/* fs has a realm name */
	FSINFO_CAP_IVER_ALL_CHANGE	= 30,	/* i_version represents data + meta changes */
	FSINFO_CAP_IVER_DATA_CHANGE	= 31,	/* i_version represents data changes only */
	FSINFO_CAP_IVER_MONO_INCR	= 32,	/* i_version incremented monotonically */
	FSINFO_CAP_SYMLINKS		= 33,	/* fs supports symlinks */
	FSINFO_CAP_HARD_LINKS		= 34,	/* fs supports hard links */
	FSINFO_CAP_HARD_LINKS_1DIR	= 35,	/* fs supports hard links in same dir only */
	FSINFO_CAP_DEVICE_FILES		= 36,	/* fs supports bdev, cdev */
	FSINFO_CAP_UNIX_SPECIALS	= 37,	/* fs supports pipe, fifo, socket */
	FSINFO_CAP_RESOURCE_FORKS	= 38,	/* fs supports resource forks/streams */
	FSINFO_CAP_NAME_CASE_INDEP	= 39,	/* Filename case independence is mandatory */
	FSINFO_CAP_NAME_NON_UTF8	= 40,	/* fs has non-utf8 names */
	FSINFO_CAP_NAME_HAS_CODEPAGE	= 41,	/* fs has a filename codepage */
	FSINFO_CAP_SPARSE		= 42,	/* fs supports sparse files */
	FSINFO_CAP_NOT_PERSISTENT	= 43,	/* fs is not persistent */
	FSINFO_CAP_NO_UNIX_MODE		= 44,	/* fs does not support unix mode bits */
	FSINFO_CAP_HAS_ATIME		= 45,	/* fs supports access time */
	FSINFO_CAP_HAS_BTIME		= 46,	/* fs supports birth/creation time */
	FSINFO_CAP_HAS_CTIME		= 47,	/* fs supports change time */
	FSINFO_CAP_HAS_MTIME		= 48,	/* fs supports modification time */
	FSINFO_CAP__NR
};

struct fsinfo_capabilities {
	__u8	capabilities[(FSINFO_CAP__NR + 7) / 8];
};

/*
 * Information struct for fsinfo(fsinfo_attr_timestamp_info).
 */
struct fsinfo_timestamp_info {
	__s64	minimum_timestamp;	/* Minimum timestamp value in seconds */
	__s64	maximum_timestamp;	/* Maximum timestamp value in seconds */
	__u16	atime_gran_mantissa;	/* Granularity(secs) = mant * 10^exp */
	__u16	btime_gran_mantissa;
	__u16	ctime_gran_mantissa;
	__u16	mtime_gran_mantissa;
	__s8	atime_gran_exponent;
	__s8	btime_gran_exponent;
	__s8	ctime_gran_exponent;
	__s8	mtime_gran_exponent;
	__u32	__reserved[1];
};

/*
 * Information struct for fsinfo(fsinfo_attr_volume_uuid).
 */
struct fsinfo_volume_uuid {
	__u8	uuid[16];
};

/*
 * Information struct for fsinfo(fsinfo_attr_server_addresses).
 *
 * Find the Mth address of the Nth server for a network mount.
 */
struct fsinfo_server_address {
	struct __kernel_sockaddr_storage address;
};

/*
 * Information struct for fsinfo(fsinfo_attr_io_size).
 *
 * Retrieve I/O size hints for a filesystem.
 */
struct fsinfo_io_size {
	__u32		dio_size_gran;	/* Size granularity for O_DIRECT */
	__u32		dio_mem_align;	/* Memory alignment for O_DIRECT */
};

/*
 * Information struct for fsinfo(fsinfo_attr_fsinfo).
 *
 * This gives information about fsinfo() itself.
 */
struct fsinfo_fsinfo {
	__u32	max_attr;	/* Number of supported attributes (fsinfo_attr__nr) */
	__u32	max_cap;	/* Number of supported capabilities (fsinfo_cap__nr) */
};

/*
 * Information struct for fsinfo(fsinfo_attr_param_description).
 *
 * Query the parameter set for a filesystem.
 */
struct fsinfo_param_description {
	__u32		nr_params;		/* Number of individual parameters */
	__u32		nr_names;		/* Number of parameter names */
	__u32		nr_enum_names;		/* Number of enum names  */
	__u32		source_param;		/* Source parameter index (or UINT_MAX) */
};

/*
 * Information struct for fsinfo(fsinfo_attr_param_specification).
 *
 * Query the specification of the Nth filesystem parameter.
 */
struct fsinfo_param_specification {
	__u32		type;		/* enum fsinfo_param_specification_type */
	__u32		flags;		/* Qualifiers */
};

enum fsinfo_param_specification_type {
	FSINFO_PARAM_SPEC_NOT_DEFINED,
	FSINFO_PARAM_SPEC_TAKES_NO_VALUE,
	FSINFO_PARAM_SPEC_IS_BOOL,
	FSINFO_PARAM_SPEC_IS_U32,
	FSINFO_PARAM_SPEC_IS_U32_OCTAL,
	FSINFO_PARAM_SPEC_IS_U32_HEX,
	FSINFO_PARAM_SPEC_IS_S32,
	FSINFO_PARAM_SPEC_IS_U64,
	FSINFO_PARAM_SPEC_IS_ENUM,
	FSINFO_PARAM_SPEC_IS_STRING,
	FSINFO_PARAM_SPEC_IS_BLOB,
	FSINFO_PARAM_SPEC_IS_BLOCKDEV,
	FSINFO_PARAM_SPEC_IS_PATH,
	FSINFO_PARAM_SPEC_IS_FD,
	NR__FSINFO_PARAM_SPEC
};

#define FSINFO_PARAM_SPEC_VALUE_IS_OPTIONAL	0X00000001
#define FSINFO_PARAM_SPEC_PREFIX_NO_IS_NEG	0X00000002
#define FSINFO_PARAM_SPEC_EMPTY_STRING_IS_NEG	0X00000004
#define FSINFO_PARAM_SPEC_DEPRECATED		0X00000008

/*
 * Information struct for fsinfo(fsinfo_attr_param_name).
 *
 * Query the Nth filesystem parameter name
 */
struct fsinfo_param_name {
	__u32		param_index;	/* Index of the parameter specification */
	char		name[252];	/* Name of the parameter */
};

/*
 * Information struct for fsinfo(fsinfo_attr_param_enum).
 *
 * Query the Nth filesystem enum parameter value name.
 */
struct fsinfo_param_enum {
	__u32		param_index;	/* Index of the relevant parameter specification */
	char		name[252];	/* Name of the enum value */
};

#endif /* _UAPI_LINUX_FSINFO_H */
