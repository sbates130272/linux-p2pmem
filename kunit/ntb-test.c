// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)

#include <kunit/test.h>
#include <linux/ntb.h>

struct ntb_test_data;

struct ntb_mock_dev {
	struct ntb_dev ntb;
	struct ntb_mock_system *sys;
	int logical_port_num;
	int physical_port_num;
};

static struct ntb_mock_dev *ntb_mock_dev(struct ntb_dev *ntb)
{
	return container_of(ntb, struct ntb_mock_dev, ntb);
}

struct ntb_mock_system {
	int nports;
	struct ntb_mock_dev port[];
};

static int ntb_mock_port_number(struct ntb_dev *ntb)
{
	return ntb_mock_dev(ntb)->physical_port_num;
}

static int ntb_mock_peer_port_count(struct ntb_dev *ntb)
{
	return ntb_mock_dev(ntb)->sys->nports - 1;
}

static int ntb_mock_peer_port_number(struct ntb_dev *ntb, int pidx)
{
	struct ntb_mock_dev *mock = ntb_mock_dev(ntb);
	int i, j;

	for (i = j = 0; i < mock->sys->nports; i++) {
		if (i == mock->logical_port_num)
			continue;
		if (j == pidx)
			return mock->sys->port[i].physical_port_num;
		j++;
	}

	return -EINVAL;
}

static const struct ntb_dev_ops ntb_mock_dev_ops = {
	.port_number = ntb_mock_port_number,
	.peer_port_count = ntb_mock_peer_port_count,
	.peer_port_number = ntb_mock_peer_port_number,
};

static int ntb_kunit_test_init(struct kunit *test, int nports,
			       int *physical_port_numbers)
{
	struct ntb_mock_system *sys;
	int i;

	sys = kzalloc(sizeof(*sys) + sizeof(*sys->port) * nports, GFP_KERNEL);
	if (!sys)
		return -ENOMEM;

	sys->nports = nports;

	for (i = 0; i < nports; i++) {
		sys->port[i].sys = sys;
		sys->port[i].ntb.ops = &ntb_mock_dev_ops;
		sys->port[i].logical_port_num = i;
		sys->port[i].physical_port_num = physical_port_numbers[i];
	}

	test->priv = sys;

	return 0;
}

static void ntb_kunit_test_exit(struct kunit *test)
{
	kfree(test->priv);
}

static int ntb_kunit_5port_test_init(struct kunit *test)
{
	int port_nums[] = {1, 5, 7, 14, 72};

	return ntb_kunit_test_init(test, ARRAY_SIZE(port_nums), port_nums);
}

static int ntb_kunit_2port_test_init(struct kunit *test)
{
	int port_nums[] = {0, 0};

	return ntb_kunit_test_init(test, ARRAY_SIZE(port_nums), port_nums);
}

static void ntb_kunit_test(struct kunit *test, struct ntb_mock_system *sys,
			   struct ntb_mock_dev *mock, int *max_resource)
{
	int peer;

	for (peer = 0; peer < ntb_peer_port_count(&mock->ntb); peer++) {
		int logical_num = ntb_peer_logical_port_number(&mock->ntb,
							       peer);
		struct ntb_dev *rem_ntb = &sys->port[logical_num].ntb;
		int res_num = ntb_peer_resource_idx(&mock->ntb, peer);
		int rem_pnum = ntb_peer_port_number(rem_ntb, res_num);

		if (res_num > *max_resource)
			*max_resource = res_num;

		KUNIT_EXPECT_EQ(test, sys->port[logical_num].physical_port_num,
				ntb_peer_port_number(&mock->ntb, peer));

		KUNIT_EXPECT_EQ(test, rem_pnum, mock->physical_port_num);
	}
}

static void ntb_kunit_test_port_numbers(struct kunit *test)
{
	struct ntb_mock_system *sys = test->priv;
	int max_resource = 0, i;

	for (i = 0; i < sys->nports; i++)
		ntb_kunit_test(test, sys, &sys->port[i], &max_resource);

	/*
	 * Each peer should use no more than (nports - 1) resource indices
	 */
	KUNIT_EXPECT_EQ(test, max_resource, sys->nports - 2);
}

static struct kunit_case ntb_kunit_test_cases[] = {
	KUNIT_CASE(ntb_kunit_test_port_numbers),
	{},
};

static struct kunit_module ntb_kunit_5port_test = {
	.name = "ntb_5port_test",
	.init = ntb_kunit_5port_test_init,
	.exit = ntb_kunit_test_exit,
	.test_cases = ntb_kunit_test_cases,
};
module_test(ntb_kunit_5port_test);

static struct kunit_module ntb_kunit_2port_test = {
	.name = "ntb_2port_test",
	.init = ntb_kunit_2port_test_init,
	.exit = ntb_kunit_test_exit,
	.test_cases = ntb_kunit_test_cases,
};
module_test(ntb_kunit_2port_test);

/*
 * The following functions shouldn't actually be used but they are
 * referenced by some of the code in the header file and not actually
 * compiled in the UM arch used by KUnit
 */
int ntb_default_peer_port_count(struct ntb_dev *ntb)
{
	return NTB_DEF_PEER_CNT;
}

int ntb_default_peer_port_number(struct ntb_dev *ntb, int pidx)
{
	return -EINVAL;
}

int ntb_default_port_number(struct ntb_dev *ntb)
{
	return -EINVAL;
}
