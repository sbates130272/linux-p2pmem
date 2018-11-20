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
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	test->priv = ctx;

	ctx->try_catch = kunit_kmalloc(test,
				       sizeof(*ctx->try_catch),
				       GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx->try_catch);
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

/*
 * Context for testing test managed resources
 * is_resource_initialized is used to test arbitrary resources
 */
struct kunit_test_resource_context {
	struct kunit test;
	bool is_resource_initialized;
};

static int fake_resource_init(struct kunit_resource *res, void *context)
{
	struct kunit_test_resource_context *ctx = context;

	res->allocation = &ctx->is_resource_initialized;
	ctx->is_resource_initialized = true;
	return 0;
}

static void fake_resource_free(struct kunit_resource *res)
{
	bool *is_resource_initialized = res->allocation;

	*is_resource_initialized = false;
}

static void kunit_resource_test_init_resources(struct kunit *test)
{
	struct kunit_test_resource_context *ctx = test->priv;

	kunit_init_test(&ctx->test, "testing_test_init_test");

	KUNIT_EXPECT_TRUE(test, list_empty(&ctx->test.resources));
}

static void kunit_resource_test_alloc_resource(struct kunit *test)
{
	struct kunit_test_resource_context *ctx = test->priv;
	struct kunit_resource *res;
	kunit_resource_free_t free = fake_resource_free;

	res = kunit_alloc_resource(&ctx->test,
				   fake_resource_init,
				   fake_resource_free,
				   ctx);

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, res);
	KUNIT_EXPECT_EQ(test, &ctx->is_resource_initialized, res->allocation);
	KUNIT_EXPECT_TRUE(test, list_is_last(&res->node, &ctx->test.resources));
	KUNIT_EXPECT_EQ(test, free, res->free);
}

static void kunit_resource_test_free_resource(struct kunit *test)
{
	struct kunit_test_resource_context *ctx = test->priv;
	struct kunit_resource *res = kunit_alloc_resource(&ctx->test,
							  fake_resource_init,
							  fake_resource_free,
							  ctx);

	kunit_free_resource(&ctx->test, res);

	KUNIT_EXPECT_EQ(test, false, ctx->is_resource_initialized);
	KUNIT_EXPECT_TRUE(test, list_empty(&ctx->test.resources));
}

#define KUNIT_RESOURCE_NUM 5
static void kunit_resource_test_cleanup_resources(struct kunit *test)
{
	int i;
	struct kunit_test_resource_context *ctx = test->priv;
	struct kunit_resource *resources[KUNIT_RESOURCE_NUM];

	for (i = 0; i < KUNIT_RESOURCE_NUM; i++) {
		resources[i] = kunit_alloc_resource(&ctx->test,
						    fake_resource_init,
						    fake_resource_free,
						    ctx);
	}

	kunit_cleanup(&ctx->test);

	KUNIT_EXPECT_TRUE(test, list_empty(&ctx->test.resources));
}

static int kunit_resource_test_init(struct kunit *test)
{
	struct kunit_test_resource_context *ctx =
			kzalloc(sizeof(*ctx), GFP_KERNEL);

	if (!ctx)
		return -ENOMEM;
	test->priv = ctx;

	kunit_init_test(&ctx->test, "test_test_context");
	return 0;
}

static void kunit_resource_test_exit(struct kunit *test)
{
	struct kunit_test_resource_context *ctx = test->priv;

	kunit_cleanup(&ctx->test);
	kfree(ctx);
}

static struct kunit_case kunit_resource_test_cases[] = {
	KUNIT_CASE(kunit_resource_test_init_resources),
	KUNIT_CASE(kunit_resource_test_alloc_resource),
	KUNIT_CASE(kunit_resource_test_free_resource),
	KUNIT_CASE(kunit_resource_test_cleanup_resources),
	{},
};

static struct kunit_module kunit_resource_test_module = {
	.name = "kunit-resource-test",
	.init = kunit_resource_test_init,
	.exit = kunit_resource_test_exit,
	.test_cases = kunit_resource_test_cases,
};
module_test(kunit_resource_test_module);
