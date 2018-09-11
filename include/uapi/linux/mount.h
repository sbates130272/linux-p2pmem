#ifndef _UAPI_LINUX_MOUNT_H
#define _UAPI_LINUX_MOUNT_H

/*
 * open_tree() flags.
 */
#define OPEN_TREE_CLONE		1		/* Clone the target tree and attach the clone */
#define OPEN_TREE_CLOEXEC	O_CLOEXEC	/* Close the file on execve() */

#endif /* _UAPI_LINUX_MOUNT_H */
