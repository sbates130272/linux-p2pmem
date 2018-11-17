// SPDX-License-Identifier: GPL-2.0
/*
 * KUnit test for core test infrastructure.
 *
 * Copyright (C) 2019, Google LLC.
 * Author: Brendan Higgins <brendanhiggins@google.com>
 */
#include <kunit/test.h>

struct kunit_try_catch_test_context {
	struct kunit_try_catch *try_catch;
	bool function_called;
};

void kunit_test_successful_try(struct kunit_try_catch_context *context)
{
	struct kunit_try_catch_test_context *ctx = context->test->priv;

	ctx->function_called = true;
}

void kunit_test_no_catch(struct kunit_try_catch_context *context)
{
	KUNIT_FAIL(context->test, "Catch should not be called.");
}

static void kunit_test_try_catch_successful_try_no_catch(struct kunit *test)
{
	struct kunit_try_catch_test_context *ctx = test->priv;
	struct kunit_try_catch *try_catch = ctx->try_catch;

	try_catch->try = kunit_test_successful_try;
	try_catch->catch = kunit_test_no_catch;
	try_catch->run(try_catch);

	KUNIT_EXPECT_TRUE(test, ctx->function_called);
}

void kunit_test_unsuccessful_try(struct kunit_try_catch_context *context)
{
	struct kunit_try_catch *try_catch = container_of(context,
							 struct kunit_try_catch,
							 context);

	try_catch->throw(try_catch);
	KUNIT_FAIL(context->test, "This line should never be reached.");
}

void kunit_test_catch(struct kunit_try_catch_context *context)
{
	struct kunit_try_catch_test_context *ctx = context->test->priv;

	ctx->function_called = true;
}

static void kunit_test_try_catch_unsuccessful_try_does_catch(struct kunit *test)
{
	struct kunit_try_catch_test_context *ctx = test->priv;
	struct kunit_try_catch *try_catch = ctx->try_catch;

	try_catch->try = kunit_test_unsuccessful_try;
	try_catch->catch = kunit_test_catch;
	try_catch->run(try_catch);

	KUNIT_EXPECT_TRUE(test, ctx->function_called);
}

static void kunit_test_generic_try_catch_successful_try_no_catch(
		struct kunit *test)
{
	struct kunit_try_catch_test_context *ctx = test->priv;
	struct kunit_try_catch *try_catch = ctx->try_catch;

	kunit_generic_try_catch_init(try_catch);

	try_catch->try = kunit_test_successful_try;
	try_catch->catch = kunit_test_no_catch;
	try_catch->run(try_catch);

	KUNIT_EXPECT_TRUE(test, ctx->function_called);
}

static void kunit_test_generic_try_catch_unsuccessful_try_does_catch(
		struct kunit *test)
{
	struct kunit_try_catch_test_context *ctx = test->priv;
	struct kunit_try_catch *try_catch = ctx->try_catch;

	kunit_generic_try_catch_init(try_catch);

	try_catch->try = kunit_test_unsuccessful_try;
	try_catch->catch = kunit_test_catch;
	try_catch->run(try_catch);

	KUNIT_EXPECT_TRUE(test, ctx->function_called);
}

static int kunit_try_catch_test_init(struct kunit *test)
{
	struct kunit_try_catch_test_context *ctx;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	test->priv = ctx;

	ctx->try_catch = kunit_kmalloc(test,
				       sizeof(*ctx->try_catch),
				       GFP_KERNEL);
	kunit_try_catch_init(ctx->try_catch);
	ctx->try_catch->context.test = test;

	return 0;
}

static struct kunit_case kunit_try_catch_test_cases[] = {
	KUNIT_CASE(kunit_test_try_catch_successful_try_no_catch),
	KUNIT_CASE(kunit_test_try_catch_unsuccessful_try_does_catch),
	KUNIT_CASE(kunit_test_generic_try_catch_successful_try_no_catch),
	KUNIT_CASE(kunit_test_generic_try_catch_unsuccessful_try_does_catch),
	{},
};

static struct kunit_module kunit_try_catch_test_module = {
	.name = "kunit-try-catch-test",
	.init = kunit_try_catch_test_init,
	.test_cases = kunit_try_catch_test_cases,
};
module_test(kunit_try_catch_test_module);
