// SPDX-License-Identifier: GPL-2.0
/*
 * Base unit test (KUnit) API.
 *
 * Copyright (C) 2019, Google LLC.
 * Author: Brendan Higgins <brendanhiggins@google.com>
 */

#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <os.h>
#include <kunit/test.h>

static bool kunit_get_success(struct kunit *test)
{
	unsigned long flags;
	bool success;

	spin_lock_irqsave(&test->lock, flags);
	success = test->success;
	spin_unlock_irqrestore(&test->lock, flags);

	return success;
}

static void kunit_set_success(struct kunit *test, bool success)
{
	unsigned long flags;

	spin_lock_irqsave(&test->lock, flags);
	test->success = success;
	spin_unlock_irqrestore(&test->lock, flags);
}

static int kunit_vprintk_emit(const struct kunit *test,
			      int level,
			      const char *fmt,
			      va_list args)
{
	return vprintk_emit(0, level, NULL, 0, fmt, args);
}

static int kunit_printk_emit(const struct kunit *test,
			     int level,
			     const char *fmt, ...)
{
	va_list args;
	int ret;

	va_start(args, fmt);
	ret = kunit_vprintk_emit(test, level, fmt, args);
	va_end(args);

	return ret;
}

static void kunit_vprintk(const struct kunit *test,
			  const char *level,
			  struct va_format *vaf)
{
	kunit_printk_emit(test,
			  level[1] - '0',
			  "kunit %s: %pV", test->name, vaf);
}

static void kunit_fail(struct kunit *test, struct kunit_stream *stream)
{
	kunit_set_success(test, false);
	stream->set_level(stream, KERN_ERR);
	stream->commit(stream);
}

int kunit_init_test(struct kunit *test, const char *name)
{
	spin_lock_init(&test->lock);
	INIT_LIST_HEAD(&test->resources);
	test->name = name;
	test->vprintk = kunit_vprintk;
	test->fail = kunit_fail;

	return 0;
}

/*
 * Initializes and runs test case. Does not clean up or do post validations.
 */
static void kunit_run_case_internal(struct kunit *test,
				    struct kunit_module *module,
				    struct kunit_case *test_case)
{
	int ret;

	if (module->init) {
		ret = module->init(test);
		if (ret) {
			kunit_err(test, "failed to initialize: %d", ret);
			kunit_set_success(test, false);
			return;
		}
	}

	test_case->run_case(test);
}

static void kunit_case_internal_cleanup(struct kunit *test)
{
	kunit_cleanup(test);
}

/*
 * Performs post validations and cleanup after a test case was run.
 * XXX: Should ONLY BE CALLED AFTER kunit_run_case_internal!
 */
static void kunit_run_case_cleanup(struct kunit *test,
				   struct kunit_module *module,
				   struct kunit_case *test_case)
{
	if (module->exit)
		module->exit(test);

	kunit_case_internal_cleanup(test);
}

/*
 * Performs all logic to run a test case.
 */
static bool kunit_run_case(struct kunit *test,
			   struct kunit_module *module,
			   struct kunit_case *test_case)
{
	kunit_set_success(test, true);

	kunit_run_case_internal(test, module, test_case);
	kunit_run_case_cleanup(test, module, test_case);

	return kunit_get_success(test);
}

int kunit_run_tests(struct kunit_module *module)
{
	bool all_passed = true, success;
	struct kunit_case *test_case;
	struct kunit test;
	int ret;

	ret = kunit_init_test(&test, module->name);
	if (ret)
		return ret;

	for (test_case = module->test_cases; test_case->run_case; test_case++) {
		success = kunit_run_case(&test, module, test_case);
		if (!success)
			all_passed = false;

		kunit_info(&test,
			  "%s %s",
			  test_case->name,
			  success ? "passed" : "failed");
	}

	if (all_passed)
		kunit_info(&test, "all tests passed");
	else
		kunit_info(&test, "one or more tests failed");

	return 0;
}

struct kunit_resource *kunit_alloc_resource(struct kunit *test,
					    kunit_resource_init_t init,
					    kunit_resource_free_t free,
					    void *context)
{
	struct kunit_resource *res;
	unsigned long flags;
	int ret;

	res = kzalloc(sizeof(*res), GFP_KERNEL);
	if (!res)
		return NULL;

	ret = init(res, context);
	if (ret)
		return NULL;

	res->free = free;
	spin_lock_irqsave(&test->lock, flags);
	list_add_tail(&res->node, &test->resources);
	spin_unlock_irqrestore(&test->lock, flags);

	return res;
}

void kunit_free_resource(struct kunit *test, struct kunit_resource *res)
{
	res->free(res);
	list_del(&res->node);
	kfree(res);
}

struct kunit_kmalloc_params {
	size_t size;
	gfp_t gfp;
};

static int kunit_kmalloc_init(struct kunit_resource *res, void *context)
{
	struct kunit_kmalloc_params *params = context;

	res->allocation = kmalloc(params->size, params->gfp);
	if (!res->allocation)
		return -ENOMEM;

	return 0;
}

static void kunit_kmalloc_free(struct kunit_resource *res)
{
	kfree(res->allocation);
}

void *kunit_kmalloc(struct kunit *test, size_t size, gfp_t gfp)
{
	struct kunit_kmalloc_params params;
	struct kunit_resource *res;

	params.size = size;
	params.gfp = gfp;

	res = kunit_alloc_resource(test,
				   kunit_kmalloc_init,
				   kunit_kmalloc_free,
				   &params);

	if (res)
		return res->allocation;
	else
		return NULL;
}

void kunit_cleanup(struct kunit *test)
{
	struct kunit_resource *resource, *resource_safe;
	unsigned long flags;

	spin_lock_irqsave(&test->lock, flags);
	list_for_each_entry_safe(resource,
				 resource_safe,
				 &test->resources,
				 node) {
		kunit_free_resource(test, resource);
	}
	spin_unlock_irqrestore(&test->lock, flags);
}

void kunit_printk(const char *level,
		  const struct kunit *test,
		  const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);

	vaf.fmt = fmt;
	vaf.va = &args;

	test->vprintk(test, level, &vaf);

	va_end(args);
}
