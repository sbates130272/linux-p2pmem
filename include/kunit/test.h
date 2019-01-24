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
#include <kunit/kunit-stream.h>

struct kunit_resource;

typedef int (*kunit_resource_init_t)(struct kunit_resource *, void *);
typedef void (*kunit_resource_free_t)(struct kunit_resource *);

/**
 * struct kunit_resource - represents a *test managed resource*
 * @allocation: for the user to store arbitrary data.
 * @free: a user supplied function to free the resource. Populated by
 * kunit_alloc_resource().
 *
 * Represents a *test managed resource*, a resource which will automatically be
 * cleaned up at the end of a test case.
 *
 * Example:
 *
 * .. code-block:: c
 *
 *	struct kunit_kmalloc_params {
 *		size_t size;
 *		gfp_t gfp;
 *	};
 *
 *	static int kunit_kmalloc_init(struct kunit_resource *res, void *context)
 *	{
 *		struct kunit_kmalloc_params *params = context;
 *		res->allocation = kmalloc(params->size, params->gfp);
 *
 *		if (!res->allocation)
 *			return -ENOMEM;
 *
 *		return 0;
 *	}
 *
 *	static void kunit_kmalloc_free(struct kunit_resource *res)
 *	{
 *		kfree(res->allocation);
 *	}
 *
 *	void *kunit_kmalloc(struct kunit *test, size_t size, gfp_t gfp)
 *	{
 *		struct kunit_kmalloc_params params;
 *		struct kunit_resource *res;
 *
 *		params.size = size;
 *		params.gfp = gfp;
 *
 *		res = kunit_alloc_resource(test, kunit_kmalloc_init,
 *			kunit_kmalloc_free, &params);
 *		if (res)
 *			return res->allocation;
 *		else
 *			return NULL;
 *	}
 */
struct kunit_resource {
	void *allocation;
	kunit_resource_free_t free;

	/* private: internal use only. */
	struct list_head node;
};

struct kunit;

/**
 * struct kunit_case - represents an individual test case.
 * @run_case: the function representing the actual test case.
 * @name: the name of the test case.
 *
 * A test case is a function with the signature, ``void (*)(struct kunit *)``
 * that makes expectations and assertions (see KUNIT_EXPECT_TRUE() and
 * KUNIT_ASSERT_TRUE()) about code under test. Each test case is associated with
 * a &struct kunit_module and will be run after the module's init function and
 * followed by the module's exit function.
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

struct kunit_try_catch_context {
	struct kunit *test;
	struct kunit_module *module;
	struct kunit_case *test_case;
	struct completion *try_completion;
	int try_result;
};

struct kunit_try_catch {
	void (*run)(struct kunit_try_catch *try_catch);
	void (*throw)(struct kunit_try_catch *try_catch);
	struct kunit_try_catch_context context;
	void (*try)(struct kunit_try_catch_context *context);
	void (*catch)(struct kunit_try_catch_context *context);
};

void kunit_try_catch_init(struct kunit_try_catch *try_catch);

void kunit_generic_try_catch_init(struct kunit_try_catch *try_catch);

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
	struct kunit_try_catch try_catch;
	spinlock_t lock; /* Gaurds all mutable test state. */
	bool success; /* Protected by lock. */
	bool death_test; /* Protected by lock. */
	struct list_head resources; /* Protected by lock. */
	void (*set_death_test)(struct kunit *test, bool death_test);
	void (*vprintk)(const struct kunit *test,
			const char *level,
			struct va_format *vaf);
	void (*fail)(struct kunit *test, struct kunit_stream *stream);
	void (*abort)(struct kunit *test);
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

/**
 * kunit_alloc_resource() - Allocates a *test managed resource*.
 * @test: The test context object.
 * @init: a user supplied function to initialize the resource.
 * @free: a user supplied function to free the resource.
 * @context: for the user to pass in arbitrary data.
 *
 * Allocates a *test managed resource*, a resource which will automatically be
 * cleaned up at the end of a test case. See &struct kunit_resource for an
 * example.
 */
struct kunit_resource *kunit_alloc_resource(struct kunit *test,
					    kunit_resource_init_t init,
					    kunit_resource_free_t free,
					    void *context);

void kunit_free_resource(struct kunit *test, struct kunit_resource *res);

/**
 * kunit_kmalloc() - Like kmalloc() except the allocation is *test managed*.
 * @test: The test context object.
 * @size: The size in bytes of the desired memory.
 * @gfp: flags passed to underlying kmalloc().
 *
 * Just like `kmalloc(...)`, except the allocation is managed by the test case
 * and is automatically cleaned up after the test case concludes. See &struct
 * kunit_resource for more information.
 */
void *kunit_kmalloc(struct kunit *test, size_t size, gfp_t gfp);

/**
 * kunit_kzalloc() - Just like kunit_kmalloc(), but zeroes the allocation.
 * @test: The test context object.
 * @size: The size in bytes of the desired memory.
 * @gfp: flags passed to underlying kmalloc().
 *
 * See kzalloc() and kunit_kmalloc() for more information.
 */
static inline void *kunit_kzalloc(struct kunit *test, size_t size, gfp_t gfp)
{
	return kunit_kmalloc(test, size, gfp | __GFP_ZERO);
}

void kunit_cleanup(struct kunit *test);

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

static inline struct kunit_stream *kunit_expect_start(struct kunit *test,
						      const char *file,
						      const char *line)
{
	struct kunit_stream *stream = kunit_new_stream(test);

	stream->add(stream, "EXPECTATION FAILED at %s:%s\n\t", file, line);

	return stream;
}

static inline void kunit_expect_end(struct kunit *test,
				    bool success,
				    struct kunit_stream *stream)
{
	if (!success)
		test->fail(test, stream);
	else
		stream->clear(stream);
}

#define KUNIT_EXPECT_START(test) \
		kunit_expect_start(test, __FILE__, __stringify(__LINE__))

#define KUNIT_EXPECT_END(test, success, stream) \
		kunit_expect_end(test, success, stream)

#define KUNIT_EXPECT_MSG(test, success, message, fmt, ...) do {		       \
	struct kunit_stream *__stream = KUNIT_EXPECT_START(test);	       \
									       \
	__stream->add(__stream, message);				       \
	__stream->add(__stream, fmt, ##__VA_ARGS__);			       \
	KUNIT_EXPECT_END(test, success, __stream);			       \
} while (0)

#define KUNIT_EXPECT(test, success, message) do {			       \
	struct kunit_stream *__stream = KUNIT_EXPECT_START(test);	       \
									       \
	__stream->add(__stream, message);				       \
	KUNIT_EXPECT_END(test, success, __stream);			       \
} while (0)

/**
 * KUNIT_SUCCEED() - A no-op expectation. Only exists for code clarity.
 * @test: The test context object.
 *
 * The opposite of KUNIT_FAIL(), it is an expectation that cannot fail. In other
 * words, it does nothing and only exists for code clarity. See
 * KUNIT_EXPECT_TRUE() for more information.
 */
#define KUNIT_SUCCEED(test) do {} while (0)

/**
 * KUNIT_FAIL() - Always causes a test to fail when evaluated.
 * @test: The test context object.
 * @fmt: an informational message to be printed when the assertion is made.
 * @...: string format arguments.
 *
 * The opposite of KUNIT_SUCCEED(), it is an expectation that always fails. In
 * other words, it always results in a failed expectation, and consequently
 * always causes the test case to fail when evaluated. See KUNIT_EXPECT_TRUE()
 * for more information.
 */
#define KUNIT_FAIL(test, fmt, ...) \
		KUNIT_EXPECT_MSG(test, false, "", fmt, ##__VA_ARGS__)

/**
 * KUNIT_EXPECT_TRUE() - Causes a test failure when the expression is not true.
 * @test: The test context object.
 * @condition: an arbitrary boolean expression. The test fails when this does
 * not evaluate to true.
 *
 * This and expectations of the form `KUNIT_EXPECT_*` will cause the test case
 * to fail when the specified condition is not met; however, it will not prevent
 * the test case from continuing to run; this is otherwise known as an
 * *expectation failure*.
 */
#define KUNIT_EXPECT_TRUE(test, condition)				       \
		KUNIT_EXPECT(test, (condition),				       \
		       "Expected " #condition " is true, but is false.")

#define KUNIT_EXPECT_TRUE_MSG(test, condition, fmt, ...)		       \
		KUNIT_EXPECT_MSG(test, (condition),			       \
				"Expected " #condition " is true, but is false.\n",\
				fmt, ##__VA_ARGS__)

/**
 * KUNIT_EXPECT_FALSE() - Makes a test failure when the expression is not false.
 * @test: The test context object.
 * @condition: an arbitrary boolean expression. The test fails when this does
 * not evaluate to false.
 *
 * Sets an expectation that @condition evaluates to false. See
 * KUNIT_EXPECT_TRUE() for more information.
 */
#define KUNIT_EXPECT_FALSE(test, condition)				       \
		KUNIT_EXPECT(test, !(condition),			       \
		       "Expected " #condition " is false, but is true.")

#define KUNIT_EXPECT_FALSE_MSG(test, condition, fmt, ...)		       \
		KUNIT_EXPECT_MSG(test, !(condition),			       \
				"Expected " #condition " is false, but is true.\n",\
				fmt, ##__VA_ARGS__)

void kunit_expect_binary_msg(struct kunit *test,
			    long long left, const char *left_name,
			    long long right, const char *right_name,
			    bool compare_result,
			    const char *compare_name,
			    const char *file,
			    const char *line,
			    const char *fmt, ...);

static inline void kunit_expect_binary(struct kunit *test,
				       long long left, const char *left_name,
				       long long right, const char *right_name,
				       bool compare_result,
				       const char *compare_name,
				       const char *file,
				       const char *line)
{
	struct kunit_stream *stream = kunit_expect_start(test, file, line);

	stream->add(stream,
		    "Expected %s %s %s, but\n",
		    left_name, compare_name, right_name);
	stream->add(stream, "\t\t%s == %lld\n", left_name, left);
	stream->add(stream, "\t\t%s == %lld", right_name, right);

	kunit_expect_end(test, compare_result, stream);
}

/*
 * A factory macro for defining the expectations for the basic comparisons
 * defined for the built in types.
 *
 * Unfortunately, there is no common type that all types can be promoted to for
 * which all the binary operators behave the same way as for the actual types
 * (for example, there is no type that long long and unsigned long long can
 * both be cast to where the comparison result is preserved for all values). So
 * the best we can do is do the comparison in the original types and then coerce
 * everything to long long for printing; this way, the comparison behaves
 * correctly and the printed out value usually makes sense without
 * interpretation, but can always be interpretted to figure out the actual
 * value.
 */
#define KUNIT_EXPECT_BINARY(test, left, condition, right) do {		       \
	typeof(left) __left = (left);					       \
	typeof(right) __right = (right);				       \
	kunit_expect_binary(test,					       \
			   (long long) __left, #left,			       \
			   (long long) __right, #right,			       \
			   __left condition __right, #condition,	       \
			   __FILE__, __stringify(__LINE__));		       \
} while (0)

#define KUNIT_EXPECT_BINARY_MSG(test, left, condition, right, fmt, ...) do {   \
	typeof(left) __left = (left);					       \
	typeof(right) __right = (right);				       \
	kunit_expect_binary_msg(test,					       \
			   (long long) __left, #left,			       \
			   (long long) __right, #right,			       \
			   __left condition __right, #condition,	       \
			   __FILE__, __stringify(__LINE__),		       \
			   fmt, ##__VA_ARGS__);				       \
} while (0)

/**
 * KUNIT_EXPECT_EQ() - Sets an expectation that @left and @right are equal.
 * @test: The test context object.
 * @left: an arbitrary expression that evaluates to a primitive C type.
 * @right: an arbitrary expression that evaluates to a primitive C type.
 *
 * Sets an expectation that the values that @left and @right evaluate to are
 * equal. This is semantically equivalent to
 * KUNIT_EXPECT_TRUE(@test, (@left) == (@right)). See KUNIT_EXPECT_TRUE() for
 * more information.
 */
#define KUNIT_EXPECT_EQ(test, left, right) \
		KUNIT_EXPECT_BINARY(test, left, ==, right)

#define KUNIT_EXPECT_EQ_MSG(test, left, right, fmt, ...)		       \
		KUNIT_EXPECT_BINARY_MSG(test,				       \
					left,				       \
					==,				       \
					right,				       \
					fmt,				       \
					##__VA_ARGS__)

/**
 * KUNIT_EXPECT_NE() - An expectation that @left and @right are not equal.
 * @test: The test context object.
 * @left: an arbitrary expression that evaluates to a primitive C type.
 * @right: an arbitrary expression that evaluates to a primitive C type.
 *
 * Sets an expectation that the values that @left and @right evaluate to are not
 * equal. This is semantically equivalent to
 * KUNIT_EXPECT_TRUE(@test, (@left) != (@right)). See KUNIT_EXPECT_TRUE() for
 * more information.
 */
#define KUNIT_EXPECT_NE(test, left, right) \
		KUNIT_EXPECT_BINARY(test, left, !=, right)

#define KUNIT_EXPECT_NE_MSG(test, left, right, fmt, ...)		       \
		KUNIT_EXPECT_BINARY_MSG(test,				       \
					left,				       \
					!=,				       \
					right,				       \
					fmt,				       \
					##__VA_ARGS__)

/**
 * KUNIT_EXPECT_LT() - An expectation that @left is less than @right.
 * @test: The test context object.
 * @left: an arbitrary expression that evaluates to a primitive C type.
 * @right: an arbitrary expression that evaluates to a primitive C type.
 *
 * Sets an expectation that the value that @left evaluates to is less than the
 * value that @right evaluates to. This is semantically equivalent to
 * KUNIT_EXPECT_TRUE(@test, (@left) < (@right)). See KUNIT_EXPECT_TRUE() for
 * more information.
 */
#define KUNIT_EXPECT_LT(test, left, right) \
		KUNIT_EXPECT_BINARY(test, left, <, right)

#define KUNIT_EXPECT_LT_MSG(test, left, right, fmt, ...)		       \
		KUNIT_EXPECT_BINARY_MSG(test,				       \
					left,				       \
					<,				       \
					right,				       \
					fmt,				       \
					##__VA_ARGS__)

/**
 * KUNIT_EXPECT_LE() - Expects that @left is less than or equal to @right.
 * @test: The test context object.
 * @left: an arbitrary expression that evaluates to a primitive C type.
 * @right: an arbitrary expression that evaluates to a primitive C type.
 *
 * Sets an expectation that the value that @left evaluates to is less than or
 * equal to the value that @right evaluates to. Semantically this is equivalent
 * to KUNIT_EXPECT_TRUE(@test, (@left) <= (@right)). See KUNIT_EXPECT_TRUE() for
 * more information.
 */
#define KUNIT_EXPECT_LE(test, left, right) \
		KUNIT_EXPECT_BINARY(test, left, <=, right)

#define KUNIT_EXPECT_LE_MSG(test, left, right, fmt, ...)		       \
		KUNIT_EXPECT_BINARY_MSG(test,				       \
					left,				       \
					<=,				       \
					right,				       \
					fmt,				       \
					##__VA_ARGS__)

/**
 * KUNIT_EXPECT_GT() - An expectation that @left is greater than @right.
 * @test: The test context object.
 * @left: an arbitrary expression that evaluates to a primitive C type.
 * @right: an arbitrary expression that evaluates to a primitive C type.
 *
 * Sets an expectation that the value that @left evaluates to is greater than
 * the value that @right evaluates to. This is semantically equivalent to
 * KUNIT_EXPECT_TRUE(@test, (@left) > (@right)). See KUNIT_EXPECT_TRUE() for
 * more information.
 */
#define KUNIT_EXPECT_GT(test, left, right) \
		KUNIT_EXPECT_BINARY(test, left, >, right)

#define KUNIT_EXPECT_GT_MSG(test, left, right, fmt, ...)		       \
		KUNIT_EXPECT_BINARY_MSG(test,				       \
					left,				       \
					>,				       \
					right,				       \
					fmt,				       \
					##__VA_ARGS__)

/**
 * KUNIT_EXPECT_GE() - Expects that @left is greater than or equal to @right.
 * @test: The test context object.
 * @left: an arbitrary expression that evaluates to a primitive C type.
 * @right: an arbitrary expression that evaluates to a primitive C type.
 *
 * Sets an expectation that the value that @left evaluates to is greater than
 * the value that @right evaluates to. This is semantically equivalent to
 * KUNIT_EXPECT_TRUE(@test, (@left) >= (@right)). See KUNIT_EXPECT_TRUE() for
 * more information.
 */
#define KUNIT_EXPECT_GE(test, left, right) \
		KUNIT_EXPECT_BINARY(test, left, >=, right)

#define KUNIT_EXPECT_GE_MSG(test, left, right, fmt, ...)		       \
		KUNIT_EXPECT_BINARY_MSG(test,				       \
					left,				       \
					>=,				       \
					right,				       \
					fmt,				       \
					##__VA_ARGS__)

/**
 * KUNIT_EXPECT_STREQ() - Expects that strings @left and @right are equal.
 * @test: The test context object.
 * @left: an arbitrary expression that evaluates to a null terminated string.
 * @right: an arbitrary expression that evaluates to a null terminated string.
 *
 * Sets an expectation that the values that @left and @right evaluate to are
 * equal. This is semantically equivalent to
 * KUNIT_EXPECT_TRUE(@test, !strcmp((@left), (@right))). See KUNIT_EXPECT_TRUE()
 * for more information.
 */
#define KUNIT_EXPECT_STREQ(test, left, right) do {			       \
	struct kunit_stream *__stream = KUNIT_EXPECT_START(test);	       \
	typeof(left) __left = (left);					       \
	typeof(right) __right = (right);				       \
									       \
	__stream->add(__stream, "Expected " #left " == " #right ", but\n");    \
	__stream->add(__stream, "\t\t%s == %s\n", #left, __left);	       \
	__stream->add(__stream, "\t\t%s == %s\n", #right, __right);	       \
									       \
	KUNIT_EXPECT_END(test, !strcmp(left, right), __stream);		       \
} while (0)

#define KUNIT_EXPECT_STREQ_MSG(test, left, right, fmt, ...) do {	       \
	struct kunit_stream *__stream = KUNIT_EXPECT_START(test);	       \
	typeof(left) __left = (left);					       \
	typeof(right) __right = (right);				       \
									       \
	__stream->add(__stream, "Expected " #left " == " #right ", but\n");    \
	__stream->add(__stream, "\t\t%s == %s\n", #left, __left);	       \
	__stream->add(__stream, "\t\t%s == %s\n", #right, __right);	       \
	__stream->add(__stream, fmt, ##__VA_ARGS__);			       \
									       \
	KUNIT_EXPECT_END(test, !strcmp(left, right), __stream);		       \
} while (0)

/**
 * KUNIT_EXPECT_STRNEQ() - Expects that strings @left and @right are not equal.
 * @test: The test context object.
 * @left: an arbitrary expression that evaluates to a null terminated string.
 * @right: an arbitrary expression that evaluates to a null terminated string.
 *
 * Sets an expectation that the values that @left and @right evaluate to are
 * not equal. This is semantically equivalent to
 * KUNIT_EXPECT_TRUE(@test, strcmp((@left), (@right))). See KUNIT_EXPECT_TRUE()
 * for more information.
 */
#define KUNIT_EXPECT_STRNEQ(test, left, right) do {			       \
	struct kunit_stream *__stream = KUNIT_EXPECT_START(test);	       \
	typeof(left) __left = (left);					       \
	typeof(right) __right = (right);				       \
									       \
	__stream->add(__stream, "Expected " #left " == " #right ", but\n");    \
	__stream->add(__stream, "\t\t%s == %s\n", #left, __left);	       \
	__stream->add(__stream, "\t\t%s == %s\n", #right, __right);	       \
									       \
	KUNIT_EXPECT_END(test, strcmp(left, right), __stream);		       \
} while (0)

#define KUNIT_EXPECT_STRNEQ_MSG(test, left, right, fmt, ...) do {	       \
	struct kunit_stream *__stream = KUNIT_EXPECT_START(test);	       \
	typeof(left) __left = (left);					       \
	typeof(right) __right = (right);				       \
									       \
	__stream->add(__stream, "Expected " #left " == " #right ", but\n");    \
	__stream->add(__stream, "\t\t%s == %s\n", #left, __left);	       \
	__stream->add(__stream, "\t\t%s == %s\n", #right, __right);	       \
	__stream->add(__stream, fmt, ##__VA_ARGS__);			       \
									       \
	KUNIT_EXPECT_END(test, strcmp(left, right), __stream);		       \
} while (0)

/**
 * KUNIT_EXPECT_NOT_ERR_OR_NULL() - Expects that @ptr is not null and not err.
 * @test: The test context object.
 * @ptr: an arbitrary pointer.
 *
 * Sets an expectation that the value that @ptr evaluates to is not null and not
 * an errno stored in a pointer. This is semantically equivalent to
 * KUNIT_EXPECT_TRUE(@test, !IS_ERR_OR_NULL(@ptr)). See KUNIT_EXPECT_TRUE() for
 * more information.
 */
#define KUNIT_EXPECT_NOT_ERR_OR_NULL(test, ptr) do {			       \
	struct kunit_stream *__stream = KUNIT_EXPECT_START(test);	       \
	typeof(ptr) __ptr = (ptr);					       \
									       \
	if (!__ptr)							       \
		__stream->add(__stream,					       \
			      "Expected " #ptr " is not null, but is.");       \
	if (IS_ERR(__ptr))						       \
		__stream->add(__stream,					       \
			      "Expected " #ptr " is not error, but is: %ld",   \
			      PTR_ERR(__ptr));				       \
									       \
	KUNIT_EXPECT_END(test, !IS_ERR_OR_NULL(__ptr), __stream);	       \
} while (0)

#define KUNIT_EXPECT_NOT_ERR_OR_NULL_MSG(test, ptr, fmt, ...) do {	       \
	struct kunit_stream *__stream = KUNIT_EXPECT_START(test);	       \
	typeof(ptr) __ptr = (ptr);					       \
									       \
	if (!__ptr) {							       \
		__stream->add(__stream,					       \
			      "Expected " #ptr " is not null, but is.");       \
		__stream->add(__stream, fmt, ##__VA_ARGS__);		       \
	}								       \
	if (IS_ERR(__ptr)) {						       \
		__stream->add(__stream,					       \
			      "Expected " #ptr " is not error, but is: %ld",   \
			      PTR_ERR(__ptr));				       \
									       \
		__stream->add(__stream, fmt, ##__VA_ARGS__);		       \
	}								       \
	KUNIT_EXPECT_END(test, !IS_ERR_OR_NULL(__ptr), __stream);	       \
} while (0)

static inline struct kunit_stream *kunit_assert_start(struct kunit *test,
						    const char *file,
						    const char *line)
{
	struct kunit_stream *stream = kunit_new_stream(test);

	stream->add(stream, "ASSERTION FAILED at %s:%s\n\t", file, line);

	return stream;
}

static inline void kunit_assert_end(struct kunit *test,
				   bool success,
				   struct kunit_stream *stream)
{
	if (!success) {
		test->fail(test, stream);
		test->abort(test);
	} else {
		stream->clear(stream);
	}
}

#define KUNIT_ASSERT_START(test) \
		kunit_assert_start(test, __FILE__, __stringify(__LINE__))

#define KUNIT_ASSERT_END(test, success, stream) \
		kunit_assert_end(test, success, stream)

#define KUNIT_ASSERT(test, success, message) do {			       \
	struct kunit_stream *__stream = KUNIT_ASSERT_START(test);	       \
									       \
	__stream->add(__stream, message);				       \
	KUNIT_ASSERT_END(test, success, __stream);			       \
} while (0)

#define KUNIT_ASSERT_MSG(test, success, message, fmt, ...) do {		       \
	struct kunit_stream *__stream = KUNIT_ASSERT_START(test);	       \
									       \
	__stream->add(__stream, message);				       \
	__stream->add(__stream, fmt, ##__VA_ARGS__);			       \
	KUNIT_ASSERT_END(test, success, __stream);			       \
} while (0)

#define KUNIT_ASSERT_FAILURE(test, fmt, ...) \
		KUNIT_ASSERT_MSG(test, false, "", fmt, ##__VA_ARGS__)

/**
 * KUNIT_ASSERT_TRUE() - Sets an assertion that @condition is true.
 * @test: The test context object.
 * @condition: an arbitrary boolean expression. The test fails and aborts when
 * this does not evaluate to true.
 *
 * This and assertions of the form `KUNIT_ASSERT_*` will cause the test case to
 * fail *and immediately abort* when the specified condition is not met. Unlike
 * an expectation failure, it will prevent the test case from continuing to run;
 * this is otherwise known as an *assertion failure*.
 */
#define KUNIT_ASSERT_TRUE(test, condition)				       \
		KUNIT_ASSERT(test, (condition),				       \
		       "Asserted " #condition " is true, but is false.")

#define KUNIT_ASSERT_TRUE_MSG(test, condition, fmt, ...)		       \
		KUNIT_ASSERT_MSG(test, (condition),			       \
				"Asserted " #condition " is true, but is false.\n",\
				fmt, ##__VA_ARGS__)

/**
 * KUNIT_ASSERT_FALSE() - Sets an assertion that @condition is false.
 * @test: The test context object.
 * @condition: an arbitrary boolean expression.
 *
 * Sets an assertion that the value that @condition evaluates to is false. This
 * is the same as KUNIT_EXPECT_FALSE(), except it causes an assertion failure
 * (see KUNIT_ASSERT_TRUE()) when the assertion is not met.
 */
#define KUNIT_ASSERT_FALSE(test, condition)				       \
		KUNIT_ASSERT(test, !(condition),			       \
		       "Asserted " #condition " is false, but is true.")

#define KUNIT_ASSERT_FALSE_MSG(test, condition, fmt, ...)		       \
		KUNIT_ASSERT_MSG(test, !(condition),			       \
				"Asserted " #condition " is false, but is true.\n",\
				fmt, ##__VA_ARGS__)

void kunit_assert_binary_msg(struct kunit *test,
			    long long left, const char *left_name,
			    long long right, const char *right_name,
			    bool compare_result,
			    const char *compare_name,
			    const char *file,
			    const char *line,
			    const char *fmt, ...);

static inline void kunit_assert_binary(struct kunit *test,
				      long long left, const char *left_name,
				      long long right, const char *right_name,
				      bool compare_result,
				      const char *compare_name,
				      const char *file,
				      const char *line)
{
	kunit_assert_binary_msg(test,
			       left, left_name,
			       right, right_name,
			       compare_result,
			       compare_name,
			       file,
			       line,
			       NULL);
}

/*
 * A factory macro for defining the expectations for the basic comparisons
 * defined for the built in types.
 *
 * Unfortunately, there is no common type that all types can be promoted to for
 * which all the binary operators behave the same way as for the actual types
 * (for example, there is no type that long long and unsigned long long can
 * both be cast to where the comparison result is preserved for all values). So
 * the best we can do is do the comparison in the original types and then coerce
 * everything to long long for printing; this way, the comparison behaves
 * correctly and the printed out value usually makes sense without
 * interpretation, but can always be interpretted to figure out the actual
 * value.
 */
#define KUNIT_ASSERT_BINARY(test, left, condition, right) do {		       \
	typeof(left) __left = (left);					       \
	typeof(right) __right = (right);				       \
	kunit_assert_binary(test,					       \
			   (long long) __left, #left,			       \
			   (long long) __right, #right,			       \
			   __left condition __right, #condition,	       \
			   __FILE__, __stringify(__LINE__));		       \
} while (0)

#define KUNIT_ASSERT_BINARY_MSG(test, left, condition, right, fmt, ...) do {   \
	typeof(left) __left = (left);					       \
	typeof(right) __right = (right);				       \
	kunit_assert_binary_msg(test,					       \
			       (long long) __left, #left,		       \
			       (long long) __right, #right,		       \
			       __left condition __right, #condition,	       \
			       __FILE__, __stringify(__LINE__),		       \
			       fmt, ##__VA_ARGS__);			       \
} while (0)

/**
 * KUNIT_ASSERT_EQ() - Sets an assertion that @left and @right are equal.
 * @test: The test context object.
 * @left: an arbitrary expression that evaluates to a primitive C type.
 * @right: an arbitrary expression that evaluates to a primitive C type.
 *
 * Sets an assertion that the values that @left and @right evaluate to are
 * equal. This is the same as KUNIT_EXPECT_EQ(), except it causes an assertion
 * failure (see KUNIT_ASSERT_TRUE()) when the assertion is not met.
 */
#define KUNIT_ASSERT_EQ(test, left, right) \
		KUNIT_ASSERT_BINARY(test, left, ==, right)

#define KUNIT_ASSERT_EQ_MSG(test, left, right, fmt, ...)		       \
		KUNIT_ASSERT_BINARY_MSG(test,				       \
					left,				       \
					==,				       \
					right,				       \
					fmt,				       \
					##__VA_ARGS__)

/**
 * KUNIT_ASSERT_NE() - An assertion that @left and @right are not equal.
 * @test: The test context object.
 * @left: an arbitrary expression that evaluates to a primitive C type.
 * @right: an arbitrary expression that evaluates to a primitive C type.
 *
 * Sets an assertion that the values that @left and @right evaluate to are not
 * equal. This is the same as KUNIT_EXPECT_NE(), except it causes an assertion
 * failure (see KUNIT_ASSERT_TRUE()) when the assertion is not met.
 */
#define KUNIT_ASSERT_NE(test, left, right) \
		KUNIT_ASSERT_BINARY(test, left, !=, right)

#define KUNIT_ASSERT_NE_MSG(test, left, right, fmt, ...)		       \
		KUNIT_ASSERT_BINARY_MSG(test,				       \
					left,				       \
					!=,				       \
					right,				       \
					fmt,				       \
					##__VA_ARGS__)

/**
 * KUNIT_ASSERT_LT() - An assertion that @left is less than @right.
 * @test: The test context object.
 * @left: an arbitrary expression that evaluates to a primitive C type.
 * @right: an arbitrary expression that evaluates to a primitive C type.
 *
 * Sets an assertion that the value that @left evaluates to is less than the
 * value that @right evaluates to. This is the same as KUNIT_EXPECT_LT(), except
 * it causes an assertion failure (see KUNIT_ASSERT_TRUE()) when the assertion
 * is not met.
 */
#define KUNIT_ASSERT_LT(test, left, right) \
		KUNIT_ASSERT_BINARY(test, left, <, right)

#define KUNIT_ASSERT_LT_MSG(test, left, right, fmt, ...)		       \
		KUNIT_ASSERT_BINARY_MSG(test,				       \
					left,				       \
					<,				       \
					right,				       \
					fmt,				       \
					##__VA_ARGS__)
/**
 * KUNIT_ASSERT_LE() - An assertion that @left is less than or equal to @right.
 * @test: The test context object.
 * @left: an arbitrary expression that evaluates to a primitive C type.
 * @right: an arbitrary expression that evaluates to a primitive C type.
 *
 * Sets an assertion that the value that @left evaluates to is less than or
 * equal to the value that @right evaluates to. This is the same as
 * KUNIT_EXPECT_LE(), except it causes an assertion failure (see
 * KUNIT_ASSERT_TRUE()) when the assertion is not met.
 */
#define KUNIT_ASSERT_LE(test, left, right) \
		KUNIT_ASSERT_BINARY(test, left, <=, right)

#define KUNIT_ASSERT_LE_MSG(test, left, right, fmt, ...)		       \
		KUNIT_ASSERT_BINARY_MSG(test,				       \
					left,				       \
					<=,				       \
					right,				       \
					fmt,				       \
					##__VA_ARGS__)
/**
 * KUNIT_ASSERT_GT() - An assertion that @left is greater than @right.
 * @test: The test context object.
 * @left: an arbitrary expression that evaluates to a primitive C type.
 * @right: an arbitrary expression that evaluates to a primitive C type.
 *
 * Sets an assertion that the value that @left evaluates to is greater than the
 * value that @right evaluates to. This is the same as KUNIT_EXPECT_GT(), except
 * it causes an assertion failure (see KUNIT_ASSERT_TRUE()) when the assertion
 * is not met.
 */
#define KUNIT_ASSERT_GT(test, left, right) \
		KUNIT_ASSERT_BINARY(test, left, >, right)

#define KUNIT_ASSERT_GT_MSG(test, left, right, fmt, ...)		       \
		KUNIT_ASSERT_BINARY_MSG(test,				       \
					left,				       \
					>,				       \
					right,				       \
					fmt,				       \
					##__VA_ARGS__)

/**
 * KUNIT_ASSERT_GE() - Assertion that @left is greater than or equal to @right.
 * @test: The test context object.
 * @left: an arbitrary expression that evaluates to a primitive C type.
 * @right: an arbitrary expression that evaluates to a primitive C type.
 *
 * Sets an assertion that the value that @left evaluates to is greater than the
 * value that @right evaluates to. This is the same as KUNIT_EXPECT_GE(), except
 * it causes an assertion failure (see KUNIT_ASSERT_TRUE()) when the assertion
 * is not met.
 */
#define KUNIT_ASSERT_GE(test, left, right) \
		KUNIT_ASSERT_BINARY(test, left, >=, right)

#define KUNIT_ASSERT_GE_MSG(test, left, right, fmt, ...)		       \
		KUNIT_ASSERT_BINARY_MSG(test,				       \
					left,				       \
					>=,				       \
					right,				       \
					fmt,				       \
					##__VA_ARGS__)

/**
 * KUNIT_ASSERT_STREQ() - An assertion that strings @left and @right are equal.
 * @test: The test context object.
 * @left: an arbitrary expression that evaluates to a null terminated string.
 * @right: an arbitrary expression that evaluates to a null terminated string.
 *
 * Sets an assertion that the values that @left and @right evaluate to are
 * equal. This is the same as KUNIT_EXPECT_STREQ(), except it causes an
 * assertion failure (see KUNIT_ASSERT_TRUE()) when the assertion is not met.
 */
#define KUNIT_ASSERT_STREQ(test, left, right) do {			       \
	struct kunit_stream *__stream = KUNIT_ASSERT_START(test);	       \
	typeof(left) __left = (left);					       \
	typeof(right) __right = (right);				       \
									       \
	__stream->add(__stream, "Asserted " #left " == " #right ", but\n");    \
	__stream->add(__stream, "\t\t%s == %s\n", #left, __left);	       \
	__stream->add(__stream, "\t\t%s == %s\n", #right, __right);	       \
									       \
	KUNIT_ASSERT_END(test, !strcmp(left, right), __stream);		       \
} while (0)

#define KUNIT_ASSERT_STREQ_MSG(test, left, right, fmt, ...) do {	       \
	struct kunit_stream *__stream = KUNIT_ASSERT_START(test);	       \
	typeof(left) __left = (left);					       \
	typeof(right) __right = (right);				       \
									       \
	__stream->add(__stream, "Asserted " #left " == " #right ", but\n");    \
	__stream->add(__stream, "\t\t%s == %s\n", #left, __left);	       \
	__stream->add(__stream, "\t\t%s == %s\n", #right, __right);	       \
	__stream->add(__stream, fmt, ##__VA_ARGS__);			       \
									       \
	KUNIT_ASSERT_END(test, !strcmp(left, right), __stream);		       \
} while (0)

/**
 * KUNIT_ASSERT_STRNEQ() - Expects that strings @left and @right are not equal.
 * @test: The test context object.
 * @left: an arbitrary expression that evaluates to a null terminated string.
 * @right: an arbitrary expression that evaluates to a null terminated string.
 *
 * Sets an expectation that the values that @left and @right evaluate to are
 * not equal. This is semantically equivalent to
 * KUNIT_ASSERT_TRUE(@test, strcmp((@left), (@right))). See KUNIT_ASSERT_TRUE()
 * for more information.
 */
#define KUNIT_ASSERT_STRNEQ(test, left, right) do {			       \
	struct kunit_stream *__stream = KUNIT_ASSERT_START(test);	       \
	typeof(left) __left = (left);					       \
	typeof(right) __right = (right);				       \
									       \
	__stream->add(__stream, "Asserted " #left " == " #right ", but\n");    \
	__stream->add(__stream, "\t\t%s == %s\n", #left, __left);	       \
	__stream->add(__stream, "\t\t%s == %s\n", #right, __right);	       \
									       \
	KUNIT_ASSERT_END(test, strcmp(left, right), __stream);		       \
} while (0)

#define KUNIT_ASSERT_STRNEQ_MSG(test, left, right, fmt, ...) do {	       \
	struct kunit_stream *__stream = KUNIT_ASSERT_START(test);	       \
	typeof(left) __left = (left);					       \
	typeof(right) __right = (right);				       \
									       \
	__stream->add(__stream, "Asserted " #left " == " #right ", but\n");    \
	__stream->add(__stream, "\t\t%s == %s\n", #left, __left);	       \
	__stream->add(__stream, "\t\t%s == %s\n", #right, __right);	       \
	__stream->add(__stream, fmt, ##__VA_ARGS__);			       \
									       \
	KUNIT_ASSERT_END(test, strcmp(left, right), __stream);		       \
} while (0)

/**
 * KUNIT_ASSERT_NOT_ERR_OR_NULL() - Assertion that @ptr is not null and not err.
 * @test: The test context object.
 * @ptr: an arbitrary pointer.
 *
 * Sets an assertion that the value that @ptr evaluates to is not null and not
 * an errno stored in a pointer. This is the same as
 * KUNIT_EXPECT_NOT_ERR_OR_NULL(), except it causes an assertion failure (see
 * KUNIT_ASSERT_TRUE()) when the assertion is not met.
 */
#define KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr) do {			       \
	struct kunit_stream *__stream = KUNIT_ASSERT_START(test);	       \
	typeof(ptr) __ptr = (ptr);					       \
									       \
	if (!__ptr)							       \
		__stream->add(__stream,					       \
			      "Asserted " #ptr " is not null, but is.");       \
	if (IS_ERR(__ptr))						       \
		__stream->add(__stream,					       \
			      "Asserted " #ptr " is not error, but is: %ld",   \
			      PTR_ERR(__ptr));				       \
									       \
	KUNIT_ASSERT_END(test, !IS_ERR_OR_NULL(__ptr), __stream);	       \
} while (0)

#define KUNIT_ASSERT_NOT_ERR_OR_NULL_MSG(test, ptr, fmt, ...) do {	       \
	struct kunit_stream *__stream = KUNIT_ASSERT_START(test);	       \
	typeof(ptr) __ptr = (ptr);					       \
									       \
	if (!__ptr) {							       \
		__stream->add(__stream,					       \
			      "Asserted " #ptr " is not null, but is.");       \
		__stream->add(__stream, fmt, ##__VA_ARGS__);		       \
	}								       \
	if (IS_ERR(__ptr)) {						       \
		__stream->add(__stream,					       \
			      "Asserted " #ptr " is not error, but is: %ld",   \
			      PTR_ERR(__ptr));				       \
									       \
		__stream->add(__stream, fmt, ##__VA_ARGS__);		       \
	}								       \
	KUNIT_ASSERT_END(test, !IS_ERR_OR_NULL(__ptr), __stream);	       \
} while (0)

#endif /* _KUNIT_TEST_H */
