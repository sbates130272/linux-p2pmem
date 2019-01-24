// SPDX-License-Identifier: GPL-2.0
/*
 * Base unit test (KUnit) API.
 *
 * Copyright (C) 2019, Google LLC.
 * Author: Brendan Higgins <brendanhiggins@google.com>
 */

#include <linux/sched/debug.h>
#include <linux/completion.h>
#include <linux/kthread.h>
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

static bool kunit_get_death_test(struct kunit *test)
{
	unsigned long flags;
	bool death_test;

	spin_lock_irqsave(&test->lock, flags);
	death_test = test->death_test;
	spin_unlock_irqrestore(&test->lock, flags);

	return death_test;
}

static void kunit_set_death_test(struct kunit *test, bool death_test)
{
	unsigned long flags;

	spin_lock_irqsave(&test->lock, flags);
	test->death_test = death_test;
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

static void __noreturn kunit_abort(struct kunit *test)
{
	kunit_set_death_test(test, true);

	test->try_catch.throw(&test->try_catch);

	/*
	 * Throw could not abort from test.
	 */
	kunit_err(test, "Throw could not abort from test!");
	show_stack(NULL, NULL);
	BUG();
}

int kunit_init_test(struct kunit *test, const char *name)
{
	spin_lock_init(&test->lock);
	INIT_LIST_HEAD(&test->resources);
	test->name = name;
	test->set_death_test = kunit_set_death_test;
	test->vprintk = kunit_vprintk;
	test->fail = kunit_fail;
	test->abort = kunit_abort;

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
 * Handles an unexpected crash in a test case.
 */
static void kunit_handle_test_crash(struct kunit *test,
				   struct kunit_module *module,
				   struct kunit_case *test_case)
{
	kunit_err(test, "%s crashed", test_case->name);
	/*
	 * TODO(brendanhiggins@google.com): This prints the stack trace up
	 * through this frame, not up to the frame that caused the crash.
	 */
	show_stack(NULL, NULL);

	kunit_case_internal_cleanup(test);
}

static void kunit_generic_throw(struct kunit_try_catch *try_catch)
{
	try_catch->context.try_result = -EFAULT;
	complete_and_exit(try_catch->context.try_completion, -EFAULT);
}

static int kunit_generic_run_threadfn_adapter(void *data)
{
	struct kunit_try_catch *try_catch = data;

	try_catch->try(&try_catch->context);

	complete_and_exit(try_catch->context.try_completion, 0);
}

static void kunit_generic_run_try_catch(struct kunit_try_catch *try_catch)
{
	struct task_struct *task_struct;
	struct kunit *test = try_catch->context.test;
	int exit_code, wake_result;
	DECLARE_COMPLETION(test_case_completion);

	try_catch->context.try_completion = &test_case_completion;
	try_catch->context.try_result = 0;
	task_struct = kthread_create(kunit_generic_run_threadfn_adapter,
					     try_catch,
					     "kunit_try_catch_thread");
	if (IS_ERR_OR_NULL(task_struct)) {
		try_catch->catch(&try_catch->context);
		return;
	}

	wake_result = wake_up_process(task_struct);
	if (wake_result != 0 && wake_result != 1) {
		kunit_err(test, "task was not woken properly: %d", wake_result);
		try_catch->catch(&try_catch->context);
	}

	/*
	 * TODO(brendanhiggins@google.com): We should probably have some type of
	 * timeout here. The only question is what that timeout value should be.
	 *
	 * The intention has always been, at some point, to be able to label
	 * tests with some type of size bucket (unit/small, integration/medium,
	 * large/system/end-to-end, etc), where each size bucket would get a
	 * default timeout value kind of like what Bazel does:
	 * https://docs.bazel.build/versions/master/be/common-definitions.html#test.size
	 * There is still some debate to be had on exactly how we do this. (For
	 * one, we probably want to have some sort of test runner level
	 * timeout.)
	 *
	 * For more background on this topic, see:
	 * https://mike-bland.com/2011/11/01/small-medium-large.html
	 */
	wait_for_completion(&test_case_completion);

	exit_code = try_catch->context.try_result;
	if (exit_code == -EFAULT)
		try_catch->catch(&try_catch->context);
	else if (exit_code == -EINTR)
		kunit_err(test, "wake_up_process() was never called.");
	else if (exit_code)
		kunit_err(test, "Unknown error: %d", exit_code);
}

void kunit_generic_try_catch_init(struct kunit_try_catch *try_catch)
{
	try_catch->run = kunit_generic_run_try_catch;
	try_catch->throw = kunit_generic_throw;
}

void __weak kunit_try_catch_init(struct kunit_try_catch *try_catch)
{
	kunit_generic_try_catch_init(try_catch);
}

static void kunit_try_run_case(struct kunit_try_catch_context *context)
{
	struct kunit_try_catch_context *ctx = context;
	struct kunit *test = ctx->test;
	struct kunit_module *module = ctx->module;
	struct kunit_case *test_case = ctx->test_case;

	/*
	 * kunit_run_case_internal may encounter a fatal error; if it does, we
	 * will jump to ENTER_HANDLER above instead of continuing normal control
	 * flow.
	 */
	kunit_run_case_internal(test, module, test_case);
	/* This line may never be reached. */
	kunit_run_case_cleanup(test, module, test_case);
}

static void kunit_catch_run_case(struct kunit_try_catch_context *context)
{
	struct kunit_try_catch_context *ctx = context;
	struct kunit *test = ctx->test;
	struct kunit_module *module = ctx->module;
	struct kunit_case *test_case = ctx->test_case;

	if (kunit_get_death_test(test)) {
		/*
		 * EXPECTED DEATH: kunit_run_case_internal encountered
		 * anticipated fatal error. Everything should be in a safe
		 * state.
		 */
		kunit_run_case_cleanup(test, module, test_case);
	} else {
		/*
		 * UNEXPECTED DEATH: kunit_run_case_internal encountered an
		 * unanticipated fatal error. We have no idea what the state of
		 * the test case is in.
		 */
		kunit_handle_test_crash(test, module, test_case);
		kunit_set_success(test, false);
	}
}

/*
 * Performs all logic to run a test case. It also catches most errors that
 * occurs in a test case and reports them as failures.
 *
 * XXX: THIS DOES NOT FOLLOW NORMAL CONTROL FLOW. READ CAREFULLY!!!
 */
static bool kunit_run_case_catch_errors(struct kunit *test,
				       struct kunit_module *module,
				       struct kunit_case *test_case)
{
	struct kunit_try_catch *try_catch = &test->try_catch;
	struct kunit_try_catch_context *context = &try_catch->context;

	kunit_try_catch_init(try_catch);

	kunit_set_success(test, true);
	kunit_set_death_test(test, false);

	/*
	 * ENTER HANDLER: If a failure occurs, we enter here.
	 */
	context->test = test;
	context->module = module;
	context->test_case = test_case;
	try_catch->try = kunit_try_run_case;
	try_catch->catch = kunit_catch_run_case;
	try_catch->run(try_catch);
	/*
	 * EXIT HANDLER: test case has been run and all possible errors have
	 * been handled.
	 */

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
		success = kunit_run_case_catch_errors(&test, module, test_case);
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

void kunit_expect_binary_msg(struct kunit *test,
			     long long left, const char *left_name,
			     long long right, const char *right_name,
			     bool compare_result,
			     const char *compare_name,
			     const char *file,
			     const char *line,
			     const char *fmt, ...)
{
	struct kunit_stream *stream = kunit_expect_start(test, file, line);
	struct va_format vaf;
	va_list args;

	stream->add(stream,
		    "Expected %s %s %s, but\n",
		    left_name, compare_name, right_name);
	stream->add(stream, "\t\t%s == %lld\n", left_name, left);
	stream->add(stream, "\t\t%s == %lld", right_name, right);

	if (fmt) {
		va_start(args, fmt);

		vaf.fmt = fmt;
		vaf.va = &args;

		stream->add(stream, "\n%pV", &vaf);

		va_end(args);
	}

	kunit_expect_end(test, compare_result, stream);
}

void kunit_assert_binary_msg(struct kunit *test,
			     long long left, const char *left_name,
			     long long right, const char *right_name,
			     bool compare_result,
			     const char *compare_name,
			     const char *file,
			     const char *line,
			     const char *fmt, ...)
{
	struct kunit_stream *stream = kunit_assert_start(test, file, line);
	struct va_format vaf;
	va_list args;

	stream->add(stream,
		    "Asserted %s %s %s, but\n",
		    left_name, compare_name, right_name);
	stream->add(stream, "\t\t%s == %lld\n", left_name, left);
	stream->add(stream, "\t\t%s == %lld", right_name, right);

	if (fmt) {
		va_start(args, fmt);

		vaf.fmt = fmt;
		vaf.va = &args;

		stream->add(stream, "\n%pV", &vaf);

		va_end(args);
	}

	kunit_assert_end(test, compare_result, stream);
}

