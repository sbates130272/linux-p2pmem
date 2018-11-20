// SPDX-License-Identifier: GPL-2.0
/*
 * Unit tests for functions defined in base.c.
 */
#include <linux/of.h>

#include <kunit/test.h>

#include "test-common.h"

static void of_unittest_find_node_by_name(struct kunit *test)
{
	struct device_node *np;
	const char *options, *name;

	np = of_find_node_by_path("/testcase-data");
	name = kasprintf(GFP_KERNEL, "%pOF", np);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, np);
	KUNIT_EXPECT_STREQ_MSG(test, "/testcase-data", name,
			       "find /testcase-data failed\n");
	of_node_put(np);
	kfree(name);

	/* Test if trailing '/' works */
	KUNIT_EXPECT_EQ_MSG(test, of_find_node_by_path("/testcase-data/"), NULL,
			    "trailing '/' on /testcase-data/ should fail\n");

	np = of_find_node_by_path("/testcase-data/phandle-tests/consumer-a");
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, np);
	name = kasprintf(GFP_KERNEL, "%pOF", np);
	KUNIT_EXPECT_STREQ_MSG(
		test, "/testcase-data/phandle-tests/consumer-a", name,
		"find /testcase-data/phandle-tests/consumer-a failed\n");
	of_node_put(np);
	kfree(name);

	np = of_find_node_by_path("testcase-alias");
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, np);
	name = kasprintf(GFP_KERNEL, "%pOF", np);
	KUNIT_EXPECT_STREQ_MSG(test, "/testcase-data", name,
			       "find testcase-alias failed\n");
	of_node_put(np);
	kfree(name);

	/* Test if trailing '/' works on aliases */
	KUNIT_EXPECT_EQ_MSG(test, of_find_node_by_path("testcase-alias/"), NULL,
			    "trailing '/' on testcase-alias/ should fail\n");

	np = of_find_node_by_path("testcase-alias/phandle-tests/consumer-a");
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, np);
	name = kasprintf(GFP_KERNEL, "%pOF", np);
	KUNIT_EXPECT_STREQ_MSG(
		test, "/testcase-data/phandle-tests/consumer-a", name,
		"find testcase-alias/phandle-tests/consumer-a failed\n");
	of_node_put(np);
	kfree(name);

	KUNIT_EXPECT_EQ_MSG(
		test,
		np = of_find_node_by_path("/testcase-data/missing-path"), NULL,
		"non-existent path returned node %pOF\n", np);
	of_node_put(np);

	KUNIT_EXPECT_EQ_MSG(
		test, np = of_find_node_by_path("missing-alias"), NULL,
		"non-existent alias returned node %pOF\n", np);
	of_node_put(np);

	KUNIT_EXPECT_EQ_MSG(
		test,
		np = of_find_node_by_path("testcase-alias/missing-path"), NULL,
		"non-existent alias with relative path returned node %pOF\n",
		np);
	of_node_put(np);

	np = of_find_node_opts_by_path("/testcase-data:testoption", &options);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, np);
	KUNIT_EXPECT_STREQ_MSG(test, "testoption", options,
			       "option path test failed\n");
	of_node_put(np);

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

	np = of_find_node_opts_by_path("/testcase-data:testoption", NULL);
	KUNIT_EXPECT_NOT_ERR_OR_NULL_MSG(test, np,
					 "NULL option path test failed\n");
	of_node_put(np);

	np = of_find_node_opts_by_path("testcase-alias:testaliasoption",
				       &options);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, np);
	KUNIT_EXPECT_STREQ_MSG(test, "testaliasoption", options,
			       "option alias path test failed\n");
	of_node_put(np);

	np = of_find_node_opts_by_path("testcase-alias:test/alias/option",
				       &options);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, np);
	KUNIT_EXPECT_STREQ_MSG(test, "test/alias/option", options,
			       "option alias path test, subcase #1 failed\n");
	of_node_put(np);

	np = of_find_node_opts_by_path("testcase-alias:testaliasoption", NULL);
	KUNIT_EXPECT_NOT_ERR_OR_NULL_MSG(
			test, np, "NULL option alias path test failed\n");
	of_node_put(np);

	options = "testoption";
	np = of_find_node_opts_by_path("testcase-alias", &options);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, np);
	KUNIT_EXPECT_EQ_MSG(test, options, NULL,
			    "option clearing test failed\n");
	of_node_put(np);

	options = "testoption";
	np = of_find_node_opts_by_path("/", &options);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, np);
	KUNIT_EXPECT_EQ_MSG(test, options, NULL,
			    "option clearing root node test failed\n");
	of_node_put(np);
}

static void of_unittest_dynamic(struct kunit *test)
{
	struct device_node *np;
	struct property *prop;

	np = of_find_node_by_path("/testcase-data");
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, np);

	/* Array of 4 properties for the purpose of testing */
	prop = kcalloc(4, sizeof(*prop), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, prop);

	/* Add a new property - should pass*/
	prop->name = "new-property";
	prop->value = "new-property-data";
	prop->length = strlen(prop->value) + 1;
	KUNIT_EXPECT_EQ_MSG(test, of_add_property(np, prop), 0,
			    "Adding a new property failed\n");

	/* Try to add an existing property - should fail */
	prop++;
	prop->name = "new-property";
	prop->value = "new-property-data-should-fail";
	prop->length = strlen(prop->value) + 1;
	KUNIT_EXPECT_NE_MSG(test, of_add_property(np, prop), 0,
			    "Adding an existing property should have failed\n");

	/* Try to modify an existing property - should pass */
	prop->value = "modify-property-data-should-pass";
	prop->length = strlen(prop->value) + 1;
	KUNIT_EXPECT_EQ_MSG(
		test, of_update_property(np, prop), 0,
		"Updating an existing property should have passed\n");

	/* Try to modify non-existent property - should pass*/
	prop++;
	prop->name = "modify-property";
	prop->value = "modify-missing-property-data-should-pass";
	prop->length = strlen(prop->value) + 1;
	KUNIT_EXPECT_EQ_MSG(test, of_update_property(np, prop), 0,
			    "Updating a missing property should have passed\n");

	/* Remove property - should pass */
	KUNIT_EXPECT_EQ_MSG(test, of_remove_property(np, prop), 0,
			    "Removing a property should have passed\n");

	/* Adding very large property - should pass */
	prop++;
	prop->name = "large-property-PAGE_SIZEx8";
	prop->length = PAGE_SIZE * 8;
	prop->value = kzalloc(prop->length, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, prop->value);
	KUNIT_EXPECT_EQ_MSG(test, of_add_property(np, prop), 0,
			    "Adding a large property should have passed\n");
}

static int of_test_init(struct kunit *test)
{
	/* adding data for unittest */
	KUNIT_ASSERT_EQ(test, 0, unittest_data_add());

	if (!of_aliases)
		of_aliases = of_find_node_by_path("/aliases");

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, of_find_node_by_path(
			"/testcase-data/phandle-tests/consumer-a"));

	return 0;
}

static struct kunit_case of_test_cases[] = {
	KUNIT_CASE(of_unittest_find_node_by_name),
	KUNIT_CASE(of_unittest_dynamic),
	{},
};

static struct kunit_module of_test_module = {
	.name = "of-base-test",
	.init = of_test_init,
	.test_cases = of_test_cases,
};
module_test(of_test_module);
