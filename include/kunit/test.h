/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Base unit test (KUnit) API.
 *
 * Copyright (C) 2019, Google LLC.
 * Author: Brendan Higgins <brendanhiggins@google.com>
 */

#ifndef _KUNIT_TEST_H
#define _KUNIT_TEST_H

#include <linux/types.h>
#include <linux/slab.h>

struct kunit;

/**
 * struct kunit_case - represents an individual test case.
 * @run_case: the function representing the actual test case.
 * @name: the name of the test case.
 *
 * A test case is a function with the signature, ``void (*)(struct kunit *)``
 * that makes expectations (see KUNIT_EXPECT_TRUE()) about code under test. Each
 * test case is associated with a &struct kunit_module and will be run after the
 * module's init function and followed by the module's exit function.
 *
 * A test case should be static and should only be created with the KUNIT_CASE()
 * macro; additionally, every array of test cases should be terminated with an
 * empty test case.
 *
 * Example:
 *
 * .. code-block:: c
 *
 *	void add_test_basic(struct kunit *test)
 *	{
 *		KUNIT_EXPECT_EQ(test, 1, add(1, 0));
 *		KUNIT_EXPECT_EQ(test, 2, add(1, 1));
 *		KUNIT_EXPECT_EQ(test, 0, add(-1, 1));
 *		KUNIT_EXPECT_EQ(test, INT_MAX, add(0, INT_MAX));
 *		KUNIT_EXPECT_EQ(test, -1, add(INT_MAX, INT_MIN));
 *	}
 *
 *	static struct kunit_case example_test_cases[] = {
 *		KUNIT_CASE(add_test_basic),
 *		{},
 *	};
 *
 */
struct kunit_case {
	void (*run_case)(struct kunit *test);
	const char name[256];

	/* private: internal use only. */
	bool success;
};

/**
 * KUNIT_CASE - A helper for creating a &struct kunit_case
 * @test_name: a reference to a test case function.
 *
 * Takes a symbol for a function representing a test case and creates a
 * &struct kunit_case object from it. See the documentation for
 * &struct kunit_case for an example on how to use it.
 */
#define KUNIT_CASE(test_name) { .run_case = test_name, .name = #test_name }

/**
 * struct kunit_module - describes a related collection of &struct kunit_case s.
 * @name: the name of the test. Purely informational.
 * @init: called before every test case.
 * @exit: called after every test case.
 * @test_cases: a null terminated array of test cases.
 *
 * A kunit_module is a collection of related &struct kunit_case s, such that
 * @init is called before every test case and @exit is called after every test
 * case, similar to the notion of a *test fixture* or a *test class* in other
 * unit testing frameworks like JUnit or Googletest.
 *
 * Every &struct kunit_case must be associated with a kunit_module for KUnit to
 * run it.
 */
struct kunit_module {
	const char name[256];
	int (*init)(struct kunit *test);
	void (*exit)(struct kunit *test);
	struct kunit_case *test_cases;
};

/**
 * struct kunit - represents a running instance of a test.
 * @priv: for user to store arbitrary data. Commonly used to pass data created
 * in the init function (see &struct kunit_module).
 *
 * Used to store information about the current context under which the test is
 * running. Most of this data is private and should only be accessed indirectly
 * via public functions; the one exception is @priv which can be used by the
 * test writer to store arbitrary data.
 */
struct kunit {
	void *priv;

	/* private: internal use only. */
	const char *name; /* Read only after initialization! */
	spinlock_t lock; /* Gaurds all mutable test state. */
	bool success; /* Protected by lock. */
	void (*vprintk)(const struct kunit *test,
			const char *level,
			struct va_format *vaf);
};

int kunit_init_test(struct kunit *test, const char *name);

int kunit_run_tests(struct kunit_module *module);

/**
 * module_test() - used to register a &struct kunit_module with KUnit.
 * @module: a statically allocated &struct kunit_module.
 *
 * Registers @module with the test framework. See &struct kunit_module for more
 * information.
 */
#define module_test(module) \
		static int module_kunit_init##module(void) \
		{ \
			return kunit_run_tests(&module); \
		} \
		late_initcall(module_kunit_init##module)

void __printf(3, 4) kunit_printk(const char *level,
				 const struct kunit *test,
				 const char *fmt, ...);

/**
 * kunit_info() - Prints an INFO level message associated with the current test.
 * @test: The test context object.
 * @fmt: A printk() style format string.
 *
 * Prints an info level message associated with the test module being run. Takes
 * a variable number of format parameters just like printk().
 */
#define kunit_info(test, fmt, ...) \
		kunit_printk(KERN_INFO, test, fmt, ##__VA_ARGS__)

/**
 * kunit_warn() - Prints a WARN level message associated with the current test.
 * @test: The test context object.
 * @fmt: A printk() style format string.
 *
 * See kunit_info().
 */
#define kunit_warn(test, fmt, ...) \
		kunit_printk(KERN_WARNING, test, fmt, ##__VA_ARGS__)

/**
 * kunit_err() - Prints an ERROR level message associated with the current test.
 * @test: The test context object.
 * @fmt: A printk() style format string.
 *
 * See kunit_info().
 */
#define kunit_err(test, fmt, ...) \
		kunit_printk(KERN_ERR, test, fmt, ##__VA_ARGS__)

#endif /* _KUNIT_TEST_H */
