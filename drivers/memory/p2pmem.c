/*
 * Peer 2 Peer Memory Device
 * Copyright (c) 2016, Microsemi Corporation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 */

#include <linux/p2pmem.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/genalloc.h>
#include <linux/memremap.h>

MODULE_DESCRIPTION("Peer 2 Peer Memory Device");
MODULE_VERSION("0.1");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Microsemi Corporation");

static struct class *p2pmem_class;
static DEFINE_IDA(p2pmem_ida);

static struct p2pmem_dev *to_p2pmem(struct device *dev)
{
	return container_of(dev, struct p2pmem_dev, dev);
}

static void p2pmem_percpu_release(struct percpu_ref *ref)
{
	struct p2pmem_dev *p = container_of(ref, struct p2pmem_dev, ref);

	complete_all(&p->cmp);
}

static void p2pmem_percpu_exit(void *data)
{
	struct percpu_ref *ref = data;

	percpu_ref_exit(ref);
}

static void p2pmem_percpu_kill(void *data)
{
	struct percpu_ref *ref = data;
	struct p2pmem_dev *p = container_of(ref, struct p2pmem_dev, ref);

	if (percpu_ref_is_dying(ref))
		return;

	percpu_ref_kill(ref);
	wait_for_completion(&p->cmp);
}

static void p2pmem_release(struct device *dev)
{
	struct p2pmem_dev *p = to_p2pmem(dev);

	if (p->pool)
		gen_pool_destroy(p->pool);

	kfree(p);
}

struct p2pmem_dev *p2pmem_create(struct device *parent)
{
	struct p2pmem_dev *p;
	int nid = dev_to_node(parent);
	int rc;

	p = kzalloc_node(sizeof(*p), GFP_KERNEL, nid);
	if (!p)
		return ERR_PTR(-ENOMEM);

	init_completion(&p->cmp);
	device_initialize(&p->dev);
	p->dev.class = p2pmem_class;
	p->dev.parent = parent;
	p->dev.release = p2pmem_release;

	p->id = ida_simple_get(&p2pmem_ida, 0, 0, GFP_KERNEL);
	if (p->id < 0) {
		rc = p->id;
		goto err_free;
	}

	dev_set_name(&p->dev, "p2pmem%d", p->id);

	p->pool = gen_pool_create(PAGE_SHIFT, nid);
	if (!p->pool) {
		rc = -ENOMEM;
		goto err_id;
	}

	rc = percpu_ref_init(&p->ref, p2pmem_percpu_release, 0,
			     GFP_KERNEL);
	if (rc)
		goto err_id;

	rc = devm_add_action_or_reset(&p->dev, p2pmem_percpu_exit, &p->ref);
	if (rc)
		goto err_id;

	rc = device_add(&p->dev);
	if (rc)
		goto err_id;

	dev_info(&p->dev, "registered");

	return p;

err_id:
	ida_simple_remove(&p2pmem_ida, p->id);
err_free:
	put_device(&p->dev);
	return ERR_PTR(rc);
}
EXPORT_SYMBOL(p2pmem_create);

void p2pmem_unregister(struct p2pmem_dev *p)
{
	if (!p)
		return;

	dev_info(&p->dev, "unregistered");
	device_del(&p->dev);
	ida_simple_remove(&p2pmem_ida, p->id);
	put_device(&p->dev);
}
EXPORT_SYMBOL(p2pmem_unregister);

int p2pmem_add_resource(struct p2pmem_dev *p, struct resource *res)
{
	int rc;
	void *addr;
	int nid = dev_to_node(&p->dev);

	addr = devm_memremap_pages(&p->dev, res, &p->ref, NULL);
	if (IS_ERR(addr))
		return PTR_ERR(addr);

	rc = gen_pool_add_virt(p->pool, (unsigned long)addr,
			       res->start, resource_size(res), nid);
	if (rc)
		return rc;

	rc = devm_add_action_or_reset(&p->dev, p2pmem_percpu_kill, &p->ref);
	if (rc)
		return rc;

	dev_info(&p->dev, "added %pR", res);

	return 0;
}
EXPORT_SYMBOL(p2pmem_add_resource);

struct pci_region {
	struct pci_dev *pdev;
	int bar;
};

static void p2pmem_release_pci_region(void *data)
{
	struct pci_region *r = data;

	pci_release_region(r->pdev, r->bar);
	kfree(r);
}

int p2pmem_add_pci_region(struct p2pmem_dev *p, struct pci_dev *pdev, int bar)
{
	int rc;
	struct pci_region *r;

	r = kzalloc(sizeof(*r), GFP_KERNEL);
	if (!r)
		return -ENOMEM;

	r->pdev = pdev;
	r->bar = bar;

	rc = pci_request_region(pdev, bar, dev_name(&p->dev));
	if (rc < 0)
		goto err_pci;

	rc = p2pmem_add_resource(p, &pdev->resource[bar]);
	if (rc < 0)
		goto err_add;

	rc = devm_add_action_or_reset(&p->dev, p2pmem_release_pci_region, r);
	if (rc)
		return rc;

	return 0;

err_add:
	pci_release_region(pdev, bar);
err_pci:
	kfree(r);
	return rc;
}
EXPORT_SYMBOL(p2pmem_add_pci_region);

void *p2pmem_alloc(struct p2pmem_dev *p, size_t size)
{
	return (void *)gen_pool_alloc(p->pool, size);
}
EXPORT_SYMBOL(p2pmem_alloc);

void p2pmem_free(struct p2pmem_dev *p, void *addr, size_t size)
{
	gen_pool_free(p->pool, (unsigned long)addr, size);
}
EXPORT_SYMBOL(p2pmem_free);

static int __match_dev_name(struct device *dev, const void *data)
{
	const char *name = data;

	return sysfs_streq(name, dev_name(dev));
}

struct p2pmem_dev *p2pmem_find_by_name(const char *name)
{
	struct device *dev;

	dev = class_find_device(p2pmem_class, NULL, name, __match_dev_name);
	if (!dev)
		return NULL;

	return to_p2pmem(dev);
}
EXPORT_SYMBOL(p2pmem_find_by_name);

void p2pmem_put(struct p2pmem_dev *p)
{
	put_device(&p->dev);
}
EXPORT_SYMBOL(p2pmem_put);

const char *p2pmem_name(struct p2pmem_dev *p)
{
	if (!p)
		return "none";

	return dev_name(&p->dev);
}
EXPORT_SYMBOL(p2pmem_name);

static int __init p2pmem_init(void)
{
	p2pmem_class = class_create(THIS_MODULE, "p2pmem");
	if (IS_ERR(p2pmem_class))
		return PTR_ERR(p2pmem_class);

	return 0;
}
module_init(p2pmem_init);

static void __exit p2pmem_exit(void)
{
	class_destroy(p2pmem_class);

	pr_info(KBUILD_MODNAME ": unloaded.\n");
}
module_exit(p2pmem_exit);
