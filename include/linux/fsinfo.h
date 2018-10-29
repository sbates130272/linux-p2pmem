/* Filesystem information query
 *
 * Copyright (C) 2018 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#ifndef _LINUX_FSINFO_H
#define _LINUX_FSINFO_H

#include <uapi/linux/fsinfo.h>

struct fsinfo_kparams {
	__u32			at_flags;	/* AT_SYMLINK_NOFOLLOW and similar */
	enum fsinfo_attribute	request;	/* What is being asking for */
	__u32			Nth;		/* Instance of it (some may have multiple) */
	__u32			Mth;		/* Subinstance */
	bool			string_val;	/* T if variable-length string value */
	void			*buffer;	/* Where to place the reply */
	size_t			buf_size;	/* Size of the buffer */
};

extern int generic_fsinfo(struct path *, struct fsinfo_kparams *);

static inline void fsinfo_set_cap(struct fsinfo_capabilities *c,
				  enum fsinfo_capability cap)
{
	c->capabilities[cap / 8] |= 1 << (cap % 8);
}

static inline void fsinfo_clear_cap(struct fsinfo_capabilities *c,
				    enum fsinfo_capability cap)
{
	c->capabilities[cap / 8] &= ~(1 << (cap % 8));
}

#endif /* _LINUX_FSINFO_H */
