// SPDX-License-Identifier: GPL-2.0
/*
 * Common code to be used by unit tests.
 */
#include "test-common.h"

#include <linux/of_fdt.h>
#include <linux/slab.h>

#include "of_private.h"

/**
 *	update_node_properties - adds the properties
 *	of np into dup node (present in live tree) and
 *	updates parent of children of np to dup.
 *
 *	@np:	node whose properties are being added to the live tree
 *	@dup:	node present in live tree to be updated
 */
static void update_node_properties(struct device_node *np,
					struct device_node *dup)
{
	struct property *prop;
	struct property *save_next;
	struct device_node *child;
	int ret;

	for_each_child_of_node(np, child)
		child->parent = dup;

	/*
	 * "unittest internal error: unable to add testdata property"
	 *
	 *    If this message reports a property in node '/__symbols__' then
	 *    the respective unittest overlay contains a label that has the
	 *    same name as a label in the live devicetree.  The label will
	 *    be in the live devicetree only if the devicetree source was
	 *    compiled with the '-@' option.  If you encounter this error,
	 *    please consider renaming __all__ of the labels in the unittest
	 *    overlay dts files with an odd prefix that is unlikely to be
	 *    used in a real devicetree.
	 */

	/*
	 * open code for_each_property_of_node() because of_add_property()
	 * sets prop->next to NULL
	 */
	for (prop = np->properties; prop != NULL; prop = save_next) {
		save_next = prop->next;
		ret = of_add_property(dup, prop);
		if (ret)
			pr_err("unittest internal error: unable to add testdata property %pOF/%s",
			       np, prop->name);
	}
}

/**
 *	attach_node_and_children - attaches nodes
 *	and its children to live tree
 *
 *	@np:	Node to attach to live tree
 */
static void attach_node_and_children(struct device_node *np)
{
	struct device_node *next, *dup, *child;
	unsigned long flags;
	const char *full_name;

	full_name = kasprintf(GFP_KERNEL, "%pOF", np);

	if (!strcmp(full_name, "/__local_fixups__") ||
	    !strcmp(full_name, "/__fixups__"))
		return;

	dup = of_find_node_by_path(full_name);
	kfree(full_name);
	if (dup) {
		update_node_properties(np, dup);
		return;
	}

	child = np->child;
	np->child = NULL;

	mutex_lock(&of_mutex);
	raw_spin_lock_irqsave(&devtree_lock, flags);
	np->sibling = np->parent->child;
	np->parent->child = np;
	of_node_clear_flag(np, OF_DETACHED);
	raw_spin_unlock_irqrestore(&devtree_lock, flags);

	__of_attach_node_sysfs(np);
	mutex_unlock(&of_mutex);

	while (child) {
		next = child->sibling;
		attach_node_and_children(child);
		child = next;
	}
}

/**
 *	unittest_data_add - Reads, copies data from
 *	linked tree and attaches it to the live tree
 */
int unittest_data_add(void)
{
	void *unittest_data;
	struct device_node *unittest_data_node, *np;
	/*
	 * __dtb_testcases_begin[] and __dtb_testcases_end[] are magically
	 * created by cmd_dt_S_dtb in scripts/Makefile.lib
	 */
	extern uint8_t __dtb_testcases_begin[];
	extern uint8_t __dtb_testcases_end[];
	const int size = __dtb_testcases_end - __dtb_testcases_begin;
	int rc;

	if (!size) {
		pr_warn("%s: No testcase data to attach; not running tests\n",
			__func__);
		return -ENODATA;
	}

	/* creating copy */
	unittest_data = kmemdup(__dtb_testcases_begin, size, GFP_KERNEL);

	if (!unittest_data) {
		pr_warn("%s: Failed to allocate memory for unittest_data; "
			"not running tests\n", __func__);
		return -ENOMEM;
	}
	of_fdt_unflatten_tree(unittest_data, NULL, &unittest_data_node);
	if (!unittest_data_node) {
		pr_warn("%s: No tree to attach; not running tests\n", __func__);
		return -ENODATA;
	}

	/*
	 * This lock normally encloses of_resolve_phandles()
	 */
	of_overlay_mutex_lock();

	rc = of_resolve_phandles(unittest_data_node);
	if (rc) {
		pr_err("%s: Failed to resolve phandles (rc=%i)\n", __func__, rc);
		of_overlay_mutex_unlock();
		return -EINVAL;
	}

	if (!of_root) {
		of_root = unittest_data_node;
		for_each_of_allnodes(np)
			__of_attach_node_sysfs(np);
		of_aliases = of_find_node_by_path("/aliases");
		of_chosen = of_find_node_by_path("/chosen");
		of_overlay_mutex_unlock();
		return 0;
	}

	/* attach the sub-tree to live tree */
	np = unittest_data_node->child;
	while (np) {
		struct device_node *next = np->sibling;

		np->parent = of_root;
		attach_node_and_children(np);
		np = next;
	}

	of_overlay_mutex_unlock();

	return 0;
}

