// SPDX-License-Identifier: GPL-2.0
/*
 * PCI Peer 2 Peer Userspace mapping tester
 *
 * Copyright (c) 2018, Eideticom Inc.
 */

#define _GNU_SOURCE

#include <fcntl.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct nvme_test_map {
	uint64_t ptr;
	uint64_t len;
	uint32_t admin_q;
};

#define NVME_IOCTL_TEST_CMD     _IOWR('N', 0x49, struct nvme_test_map)

static int kmsg_flush(int kmsg_fd)
{
	char buf[4096];
	int ret = 0;

	while (ret != -1)
		ret = read(kmsg_fd, buf, sizeof(buf));

	if (errno == EAGAIN)
		return 0;

	return ret;
}

static void kmsg_dump(int kmsg_fd)
{
	char buf[4096], *start, *end;
	int ret;

	while (1) {
		ret = read(kmsg_fd, buf, sizeof(buf));
		if (ret == -1) {
			if (errno == -EPIPE)
				continue;
			break;
		}

		start = strchr(buf, ';') + 1;
		end = strchr(start, '\n');

		*end = 0;

		printf("%s\n", start);
	}
}

__attribute__((format (printf, 2, 3)))
static void kmsg_printf(int kmsg_fd, char *fmt, ...)
{
	char buf[4096];
	va_list args;
	int ret;

	va_start(args, fmt);
	ret = vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	if (ret == sizeof(buf))
		buf[ret - 1] = 0;

	ret = write(kmsg_fd, buf, ret);
}

enum {
	HAS_P2PDMA	= 1 << 0,
	USE_ADMIN_QUEUE	= 1 << 1,
};

static int run_ioctl_test(int fd, void *addr, size_t len, int kmsg_fd,
			  int flags)
{
	struct nvme_test_map m = {
		.ptr = (uint64_t)addr,
		.len = len,
		.admin_q = !!(flags & USE_ADMIN_QUEUE),
	};
	int ret, tmp, expected_fail;

	expected_fail = flags == (USE_ADMIN_QUEUE | HAS_P2PDMA);

	ret = ioctl(fd, NVME_IOCTL_TEST_CMD, &m);
	tmp = errno;
	kmsg_dump(kmsg_fd);
	if (ret < 0) {
		errno = tmp;
		fprintf(stderr, "Test Map IOCTL Failed: %m%s\n",
		        expected_fail ? " (expected)" : "");
		return expected_fail ? 0 : -1;
	}

	if (expected_fail)
		fprintf(stderr, "Expected a failure here but didn't get one!\n");

	return expected_fail ? -1 : 0;
}

static int test_p2pdma_mmap(int mmap_fd, int ioctl_fd, int kmsg_fd)

{
	const size_t sz = 3 << 15;
	void *addr, *p2p_addr;
	int ret;

	addr = mmap(NULL, sz, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED) {
		fprintf(stderr, "Unable to create anonymous mapping: %m\n");
		return -1;
	}

	p2p_addr = mmap(addr + sz / 3, sz / 3, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_FIXED, mmap_fd, 0);
	if (p2p_addr == MAP_FAILED) {
		fprintf(stderr, "Unable to create p2pdma mapping: %m\n");
		ret = -1;
		goto out_unmap;
	}

	printf("\n");
	kmsg_printf(kmsg_fd, "------- Map Test with Only Regular Memory\n");
	ret = run_ioctl_test(ioctl_fd, addr, sz / 3, kmsg_fd, 0);
	if (ret)
		goto out_unmap;

	printf("\n");
	kmsg_printf(kmsg_fd, "------- Map Test with Only P2PDMA Memory\n");
	ret = run_ioctl_test(ioctl_fd, p2p_addr, sz / 3, kmsg_fd, HAS_P2PDMA);
	if (ret)
		goto out_unmap;

	printf("\n");
	kmsg_printf(kmsg_fd, "------- Map Test with Only P2PDMA Memory on unsupported queue\n");
	ret = run_ioctl_test(ioctl_fd, p2p_addr, sz / 3, kmsg_fd,
			     HAS_P2PDMA | USE_ADMIN_QUEUE);
	if (ret)
		goto out_unmap;

	printf("\n");
	kmsg_printf(kmsg_fd, "------- Map Test with Regular/P2PDMA Memory\n");
	ret = run_ioctl_test(ioctl_fd, addr, sz * 2 / 3, kmsg_fd, HAS_P2PDMA);
	if (ret)
		goto out_unmap;

	printf("\n");
	kmsg_printf(kmsg_fd, "------- Map Test with Regular/P2PDMA Memory on unsupported queue\n");
	ret = run_ioctl_test(ioctl_fd, addr, sz * 2 / 3, kmsg_fd,
			     HAS_P2PDMA | USE_ADMIN_QUEUE);
	if (ret)
		goto out_unmap;

	printf("\n");
	kmsg_printf(kmsg_fd, "------- Map Test with P2PDMA/Regular Memory\n");
	ret = run_ioctl_test(ioctl_fd, p2p_addr, sz * 2 / 3, kmsg_fd,
			     HAS_P2PDMA);
	if (ret)
		goto out_unmap;

	printf("\n");
	kmsg_printf(kmsg_fd, "------- Map Test with Regular/P2PDMA/Regular Memory\n");
	ret = run_ioctl_test(ioctl_fd, addr, sz, kmsg_fd, HAS_P2PDMA);
	if (ret)
		goto out_unmap;

	printf("\n");
	kmsg_printf(kmsg_fd, "------- Map Test with Regular/P2PDMA/Regular With Offset\n");
	ret = run_ioctl_test(ioctl_fd, addr + 512, sz - 1024, kmsg_fd,
			     HAS_P2PDMA);
	if (ret)
		goto out_unmap;

out_unmap:
	if (munmap(addr, sz))
		fprintf(stderr, "Unable to unmap the mapping: %m\n");

	return ret;
}

static int is_nvme_ctrl(int fd)
{
	char sysfs_path[PATH_MAX], subsys_path[PATH_MAX];
	struct stat stat;
	ssize_t ret;

	ret = fstat(fd, &stat);
	if (ret < 0)
		return ret;

	if (!S_ISCHR(stat.st_mode))
		return 0;

	snprintf(sysfs_path, PATH_MAX, "/sys/dev/char/%d:%d/subsystem",
		 major(stat.st_rdev), minor(stat.st_rdev));

	ret = readlink(sysfs_path, subsys_path, sizeof(subsys_path));
	if (ret < 0 || ret == PATH_MAX)
		return 0;

	if (strcmp(basename(subsys_path), "nvme"))
		return 0;

	return 1;
}

int main(int argc, char *argv[])
{
	int mmap_fd, ioctl_fd, kmsg_fd, ret;
	const char *ioctl_dev;

	if (argc < 2 || argc > 3) {
		fprintf(stderr, "USAGE: %s MMAP-DEV [NVME-CTRL-DEV]\n",
			argv[0]);
		return -1;
	}

	mmap_fd = open(argv[1], O_RDWR);
	if (mmap_fd < 0) {
		fprintf(stderr, "Unable to open '%s': %m\n", argv[1]);
		return -1;
	}

	ioctl_dev = argv[1];
	ioctl_fd = mmap_fd;

	if (argc == 3) {
		ioctl_dev = argv[2];
		ioctl_fd = open(argv[2], O_RDWR);
		if (ioctl_fd < 0) {
			fprintf(stderr, "Unable to open '%s': %m\n", argv[2]);
			goto close_mmap_fd;
		}
	}

	ret = is_nvme_ctrl(ioctl_fd);
	if (ret < 0) {
		fprintf(stderr, "Failed to determine if '%s' is an NVME Controller: %m\n",
			ioctl_dev);
		goto close_mmap_fd;
	} else if (!ret)  {
		fprintf(stderr, "Not an NVME controller: %s\n", ioctl_dev);
		ret = -1;
		goto close_mmap_fd;
	}

	kmsg_fd = open("/dev/kmsg", O_RDWR | O_NONBLOCK);
	if (kmsg_fd < 0) {
		fprintf(stderr, "Unable to open /dev/kmsg: %m\n");
		ret = -1;
		goto close_mmap_fd;
	}

	ret = kmsg_flush(kmsg_fd);
	if (ret < 0) {
		fprintf(stderr, "Unable to flush kmsg fd: %m\n");
		ret = -1;
		goto close_kmsg_fd;
	}

	ret = test_p2pdma_mmap(mmap_fd, ioctl_fd, kmsg_fd);

close_kmsg_fd:
	close(kmsg_fd);
close_mmap_fd:
	close(mmap_fd);
	if (mmap_fd != ioctl_fd)
		close(ioctl_fd);
	return ret;
}
