// SPDX-License-Identifier: GPL-2.0
/*
 * Unit tests for functions defined in base.c.
 */
#include <linux/of.h>

#include <kunit/test.h>

#include "test-common.h"

static void of_test_find_node_by_name_basic(struct kunit *test)
{
	struct device_node *np;
	const char *name;

	np = of_find_node_by_path("/testcase-data");
	name = kasprintf(GFP_KERNEL, "%pOF", np);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, np);
	KUNIT_EXPECT_STREQ_MSG(test, "/testcase-data", name,
			       "find /testcase-data failed\n");
	of_node_put(np);
	kfree(name);
}

static void of_test_find_node_by_name_trailing_slash(struct kunit *test)
{
	/* Test if trailing '/' works */
	KUNIT_EXPECT_EQ_MSG(test, of_find_node_by_path("/testcase-data/"), NULL,
			    "trailing '/' on /testcase-data/ should fail\n");

}

static void of_test_find_node_by_name_multiple_components(struct kunit *test)
{
	struct device_node *np;
	const char *name;

	np = of_find_node_by_path("/testcase-data/phandle-tests/consumer-a");
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, np);
	name = kasprintf(GFP_KERNEL, "%pOF", np);
	KUNIT_EXPECT_STREQ_MSG(
		test, "/testcase-data/phandle-tests/consumer-a", name,
		"find /testcase-data/phandle-tests/consumer-a failed\n");
	of_node_put(np);
	kfree(name);
}

static void of_test_find_node_by_name_with_alias(struct kunit *test)
{
	struct device_node *np;
	const char *name;

	np = of_find_node_by_path("testcase-alias");
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, np);
	name = kasprintf(GFP_KERNEL, "%pOF", np);
	KUNIT_EXPECT_STREQ_MSG(test, "/testcase-data", name,
			       "find testcase-alias failed\n");
	of_node_put(np);
	kfree(name);
}

static void of_test_find_node_by_name_with_alias_and_slash(struct kunit *test)
{
	/* Test if trailing '/' works on aliases */
	KUNIT_EXPECT_EQ_MSG(test, of_find_node_by_path("testcase-alias/"), NULL,
			   "trailing '/' on testcase-alias/ should fail\n");
}

/*
 * TODO(brendanhiggins@google.com): This looks like a duplicate of
 * of_test_find_node_by_name_multiple_components
 */
static void of_test_find_node_by_name_multiple_components_2(struct kunit *test)
{
	struct device_node *np;
	const char *name;

	np = of_find_node_by_path("testcase-alias/phandle-tests/consumer-a");
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, np);
	name = kasprintf(GFP_KERNEL, "%pOF", np);
	KUNIT_EXPECT_STREQ_MSG(
		test, "/testcase-data/phandle-tests/consumer-a", name,
		"find testcase-alias/phandle-tests/consumer-a failed\n");
	of_node_put(np);
	kfree(name);
}

static void of_test_find_node_by_name_missing_path(struct kunit *test)
{
	struct device_node *np;

	KUNIT_EXPECT_EQ_MSG(
		test,
		np = of_find_node_by_path("/testcase-data/missing-path"), NULL,
		"non-existent path returned node %pOF\n", np);
	of_node_put(np);
}

static void of_test_find_node_by_name_missing_alias(struct kunit *test)
{
	struct device_node *np;

	KUNIT_EXPECT_EQ_MSG(
		test, np = of_find_node_by_path("missing-alias"), NULL,
		"non-existent alias returned node %pOF\n", np);
	of_node_put(np);
}

static void of_test_find_node_by_name_missing_alias_with_relative_path(
		struct kunit *test)
{
	struct device_node *np;

	KUNIT_EXPECT_EQ_MSG(
		test,
		np = of_find_node_by_path("testcase-alias/missing-path"), NULL,
		"non-existent alias with relative path returned node %pOF\n",
		np);
	of_node_put(np);
}

static void of_test_find_node_by_name_with_option(struct kunit *test)
{
	struct device_node *np;
	const char *options;

	np = of_find_node_opts_by_path("/testcase-data:testoption", &options);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, np);
	KUNIT_EXPECT_STREQ_MSG(test, "testoption", options,
			       "option path test failed\n");
	of_node_put(np);
}

static void of_test_find_node_by_name_with_option_and_slash(struct kunit *test)
{
	struct device_node *np;
	const char *options;

	np = of_find_node_opts_by_path("/testcase-data:test/option", &options);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, np);
	KUNIT_EXPECT_STREQ_MSG(test, "test/option", options,
			       "option path test, subcase #1 failed\n");
	of_node_put(np);

	np = of_find_node_opts_by_path("/testcase-data/testcase-device1:test/option", &options);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, np);
	KUNIT_EXPECT_STREQ_MSG(test, "test/option", options,
			       "option path test, subcase #2 failed\n");
	of_node_put(np);
}

static void of_test_find_node_by_name_with_null_option(struct kunit *test)
{
	struct device_node *np;

	np = of_find_node_opts_by_path("/testcase-data:testoption", NULL);
	KUNIT_EXPECT_NOT_ERR_OR_NULL_MSG(test, np,
					 "NULL option path test failed\n");
	of_node_put(np);
}

static void of_test_find_node_by_name_with_option_alias(struct kunit *test)
{
	struct device_node *np;
	const char *options;

	np = of_find_node_opts_by_path("testcase-alias:testaliasoption",
				       &options);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, np);
	KUNIT_EXPECT_STREQ_MSG(test, "testaliasoption", options,
			       "option alias path test failed\n");
	of_node_put(np);
}

static void of_test_find_node_by_name_with_option_alias_and_slash(
		struct kunit *test)
{
	struct device_node *np;
	const char *options;

	np = of_find_node_opts_by_path("testcase-alias:test/alias/option",
				       &options);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, np);
	KUNIT_EXPECT_STREQ_MSG(test, "test/alias/option", options,
			       "option alias path test, subcase #1 failed\n");
	of_node_put(np);
}

static void of_test_find_node_by_name_with_null_option_alias(struct kunit *test)
{
	struct device_node *np;

	np = of_find_node_opts_by_path("testcase-alias:testaliasoption", NULL);
	KUNIT_EXPECT_NOT_ERR_OR_NULL_MSG(
			test, np, "NULL option alias path test failed\n");
	of_node_put(np);
}

static void of_test_find_node_by_name_option_clearing(struct kunit *test)
{
	struct device_node *np;
	const char *options;

	options = "testoption";
	np = of_find_node_opts_by_path("testcase-alias", &options);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, np);
	KUNIT_EXPECT_EQ_MSG(test, options, NULL,
			    "option clearing test failed\n");
	of_node_put(np);
}

static void of_test_find_node_by_name_option_clearing_root(struct kunit *test)
{
	struct device_node *np;
	const char *options;

	options = "testoption";
	np = of_find_node_opts_by_path("/", &options);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, np);
	KUNIT_EXPECT_EQ_MSG(test, options, NULL,
			    "option clearing root node test failed\n");
	of_node_put(np);
}

static int of_test_find_node_by_name_init(struct kunit *test)
{
	/* adding data for unittest */
	KUNIT_ASSERT_EQ(test, 0, unittest_data_add());

	if (!of_aliases)
		of_aliases = of_find_node_by_path("/aliases");

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, of_find_node_by_path(
			"/testcase-data/phandle-tests/consumer-a"));

	return 0;
}

static struct kunit_case of_test_find_node_by_name_cases[] = {
	KUNIT_CASE(of_test_find_node_by_name_basic),
	KUNIT_CASE(of_test_find_node_by_name_trailing_slash),
	KUNIT_CASE(of_test_find_node_by_name_multiple_components),
	KUNIT_CASE(of_test_find_node_by_name_with_alias),
	KUNIT_CASE(of_test_find_node_by_name_with_alias_and_slash),
	KUNIT_CASE(of_test_find_node_by_name_multiple_components_2),
	KUNIT_CASE(of_test_find_node_by_name_missing_path),
	KUNIT_CASE(of_test_find_node_by_name_missing_alias),
	KUNIT_CASE(of_test_find_node_by_name_missing_alias_with_relative_path),
	KUNIT_CASE(of_test_find_node_by_name_with_option),
	KUNIT_CASE(of_test_find_node_by_name_with_option_and_slash),
	KUNIT_CASE(of_test_find_node_by_name_with_null_option),
	KUNIT_CASE(of_test_find_node_by_name_with_option_alias),
	KUNIT_CASE(of_test_find_node_by_name_with_option_alias_and_slash),
	KUNIT_CASE(of_test_find_node_by_name_with_null_option_alias),
	KUNIT_CASE(of_test_find_node_by_name_option_clearing),
	KUNIT_CASE(of_test_find_node_by_name_option_clearing_root),
	{},
};

static struct kunit_module of_test_find_node_by_name_module = {
	.name = "of-test-find-node-by-name",
	.init = of_test_find_node_by_name_init,
	.test_cases = of_test_find_node_by_name_cases,
};
module_test(of_test_find_node_by_name_module);

struct of_test_dynamic_context {
	struct device_node *np;
	struct property *prop0;
	struct property *prop1;
};

static void of_test_dynamic_basic(struct kunit *test)
{
	struct of_test_dynamic_context *ctx = test->priv;
	struct device_node *np = ctx->np;
	struct property *prop0 = ctx->prop0;

	/* Add a new property - should pass*/
	prop0->name = "new-property";
	prop0->value = "new-property-data";
	prop0->length = strlen(prop0->value) + 1;
	KUNIT_EXPECT_EQ_MSG(test, of_add_property(np, prop0), 0,
			    "Adding a new property failed\n");

	/* Test that we can remove a property */
	KUNIT_EXPECT_EQ(test, of_remove_property(np, prop0), 0);
}

static void of_test_dynamic_add_existing_property(struct kunit *test)
{
	struct of_test_dynamic_context *ctx = test->priv;
	struct device_node *np = ctx->np;
	struct property *prop0 = ctx->prop0, *prop1 = ctx->prop1;

	/* Add a new property - should pass*/
	prop0->name = "new-property";
	prop0->value = "new-property-data";
	prop0->length = strlen(prop0->value) + 1;
	KUNIT_EXPECT_EQ_MSG(test, of_add_property(np, prop0), 0,
			    "Adding a new property failed\n");

	/* Try to add an existing property - should fail */
	prop1->name = "new-property";
	prop1->value = "new-property-data-should-fail";
	prop1->length = strlen(prop1->value) + 1;
	KUNIT_EXPECT_NE_MSG(test, of_add_property(np, prop1), 0,
			    "Adding an existing property should have failed\n");
}

static void of_test_dynamic_modify_existing_property(struct kunit *test)
{
	struct of_test_dynamic_context *ctx = test->priv;
	struct device_node *np = ctx->np;
	struct property *prop0 = ctx->prop0, *prop1 = ctx->prop1;

	/* Add a new property - should pass*/
	prop0->name = "new-property";
	prop0->value = "new-property-data";
	prop0->length = strlen(prop0->value) + 1;
	KUNIT_EXPECT_EQ_MSG(test, of_add_property(np, prop0), 0,
			    "Adding a new property failed\n");

	/* Try to modify an existing property - should pass */
	prop1->name = "new-property";
	prop1->value = "modify-property-data-should-pass";
	prop1->length = strlen(prop1->value) + 1;
	KUNIT_EXPECT_EQ_MSG(test, of_update_property(np, prop1), 0,
			    "Updating an existing property should have passed\n");
}

static void of_test_dynamic_modify_non_existent_property(struct kunit *test)
{
	struct of_test_dynamic_context *ctx = test->priv;
	struct device_node *np = ctx->np;
	struct property *prop0 = ctx->prop0;

	/* Try to modify non-existent property - should pass*/
	prop0->name = "modify-property";
	prop0->value = "modify-missing-property-data-should-pass";
	prop0->length = strlen(prop0->value) + 1;
	KUNIT_EXPECT_EQ_MSG(test, of_update_property(np, prop0), 0,
			    "Updating a missing property should have passed\n");
}

static void of_test_dynamic_large_property(struct kunit *test)
{
	struct of_test_dynamic_context *ctx = test->priv;
	struct device_node *np = ctx->np;
	struct property *prop0 = ctx->prop0;

	/* Adding very large property - should pass */
	prop0->name = "large-property-PAGE_SIZEx8";
	prop0->length = PAGE_SIZE * 8;
	prop0->value = kunit_kzalloc(test, prop0->length, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, prop0->value);

	KUNIT_EXPECT_EQ_MSG(test, of_add_property(np, prop0), 0,
			    "Adding a large property should have passed\n");
}

static int of_test_dynamic_init(struct kunit *test)
{
	struct of_test_dynamic_context *ctx;

	KUNIT_ASSERT_EQ(test, 0, unittest_data_add());

	if (!of_aliases)
		of_aliases = of_find_node_by_path("/aliases");

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, of_find_node_by_path(
			"/testcase-data/phandle-tests/consumer-a"));

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	test->priv = ctx;

	ctx->np = of_find_node_by_path("/testcase-data");
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx->np);

	ctx->prop0 = kunit_kzalloc(test, sizeof(*ctx->prop0), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx->prop0);

	ctx->prop1 = kunit_kzalloc(test, sizeof(*ctx->prop1), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx->prop1);

	return 0;
}

static void of_test_dynamic_exit(struct kunit *test)
{
	struct of_test_dynamic_context *ctx = test->priv;
	struct device_node *np = ctx->np;

	of_remove_property(np, ctx->prop0);
	of_remove_property(np, ctx->prop1);
	of_node_put(np);
}

static struct kunit_case of_test_dynamic_cases[] = {
	KUNIT_CASE(of_test_dynamic_basic),
	KUNIT_CASE(of_test_dynamic_add_existing_property),
	KUNIT_CASE(of_test_dynamic_modify_existing_property),
	KUNIT_CASE(of_test_dynamic_modify_non_existent_property),
	KUNIT_CASE(of_test_dynamic_large_property),
	{},
};

static struct kunit_module of_test_dynamic_module = {
	.name = "of-dynamic-test",
	.init = of_test_dynamic_init,
	.exit = of_test_dynamic_exit,
	.test_cases = of_test_dynamic_cases,
};
module_test(of_test_dynamic_module);
