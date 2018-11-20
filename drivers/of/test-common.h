/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Common code to be used by unit tests.
 */
#ifndef _LINUX_OF_TEST_COMMON_H
#define _LINUX_OF_TEST_COMMON_H

#include <linux/of.h>

/**
 *	unittest_data_add - Reads, copies data from
 *	linked tree and attaches it to the live tree
 */
int unittest_data_add(void);

#endif /* _LINUX_OF_TEST_COMMON_H */
