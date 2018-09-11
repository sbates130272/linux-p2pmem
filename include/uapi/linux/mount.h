#ifndef _UAPI_LINUX_MOUNT_H
#define _UAPI_LINUX_MOUNT_H

/*
 * open_tree() flags.
 */
#define OPEN_TREE_CLONE		1		/* Clone the target tree and attach the clone */
#define OPEN_TREE_CLOEXEC	O_CLOEXEC	/* Close the file on execve() */

/*
 * move_mount() flags.
 */
#define MOVE_MOUNT_F_SYMLINKS		0x00000001 /* Follow symlinks on from path */
#define MOVE_MOUNT_F_AUTOMOUNTS		0x00000002 /* Follow automounts on from path */
#define MOVE_MOUNT_F_EMPTY_PATH		0x00000004 /* Empty from path permitted */
#define MOVE_MOUNT_T_SYMLINKS		0x00000010 /* Follow symlinks on to path */
#define MOVE_MOUNT_T_AUTOMOUNTS		0x00000020 /* Follow automounts on to path */
#define MOVE_MOUNT_T_EMPTY_PATH		0x00000040 /* Empty to path permitted */
#define MOVE_MOUNT__MASK		0x00000077

#endif /* _UAPI_LINUX_MOUNT_H */
