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
#include <linux/debugfs.h>
#include <linux/pfn_t.h>

MODULE_DESCRIPTION("Peer 2 Peer Memory Device");
MODULE_VERSION("0.1");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Microsemi Corporation");

static int max_devices = 16;
module_param(max_devices, int, 0444);
MODULE_PARM_DESC(max_devices, "Maximum number of char devices");

static struct class *p2pmem_class;
static DEFINE_IDA(p2pmem_ida);
static dev_t p2pmem_devt;

static struct dentry *p2pmem_debugfs_root;

static int stats_show(struct seq_file *seq, void *v)
{
	struct p2pmem_dev *p = seq->private;

	if (p->pool) {
		seq_printf(seq, "total size: %zu\n", gen_pool_size(p->pool));
		seq_printf(seq, "available:  %zu\n", gen_pool_avail(p->pool));
	}
	return 0;
}

static int stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, stats_show, inode->i_private);
}

static const struct file_operations stats_debugfs_fops = {
	.owner   = THIS_MODULE,
	.open    = stats_open,
	.release = single_release,
	.read	 = seq_read,
	.llseek  = seq_lseek,
};

static void setup_debugfs(struct p2pmem_dev *p)
{
	struct dentry *de;

	de = debugfs_create_file("stats", 0400, p->debugfs_root,
				 (void *)p, &stats_debugfs_fops);
}

static struct p2pmem_dev *to_p2pmem(struct device *dev)
{
	return container_of(dev, struct p2pmem_dev, dev);
}

struct p2pmem_vma {
	struct p2pmem_dev *p2pmem_dev;
	atomic_t mmap_count;
	size_t nr_pages;

	/* Protects the used_pages array */
	struct mutex mutex;
	struct page *used_pages[];
};

static void p2pmem_vma_open(struct vm_area_struct *vma)
{
	struct p2pmem_vma *pv = vma->vm_private_data;

	atomic_inc(&pv->mmap_count);
}

static void p2pmem_vma_free_pages(struct vm_area_struct *vma)
{
	int i;
	struct p2pmem_vma *pv = vma->vm_private_data;

	mutex_lock(&pv->mutex);

	for (i = 0; i < pv->nr_pages; i++) {
		if (pv->used_pages[i]) {
			p2pmem_free_page(pv->p2pmem_dev, pv->used_pages[i]);
			pv->used_pages[i] = NULL;
		}
	}

	mutex_unlock(&pv->mutex);
}

static void p2pmem_vma_close(struct vm_area_struct *vma)
{
	struct p2pmem_vma *pv = vma->vm_private_data;

	if (!atomic_dec_and_test(&pv->mmap_count))
		return;

	p2pmem_vma_free_pages(vma);

	dev_dbg(&pv->p2pmem_dev->dev, "vma close");
	kfree(pv);
}

static int p2pmem_vma_fault(struct vm_fault *vmf)
{
	struct p2pmem_vma *pv = vmf->vma->vm_private_data;
	unsigned int pg_idx;
	struct page *pg;
	pfn_t pfn;
	int rc;

	if (!pv->p2pmem_dev->alive)
		return VM_FAULT_SIGBUS;

	pg_idx = (vmf->address - vmf->vma->vm_start) / PAGE_SIZE;

	mutex_lock(&pv->mutex);

	if (pv->used_pages[pg_idx])
		pg = pv->used_pages[pg_idx];
	else
		pg = p2pmem_alloc_page(pv->p2pmem_dev);

	if (!pg) {
		mutex_unlock(&pv->mutex);
		return VM_FAULT_OOM;
	}

	pv->used_pages[pg_idx] = pg;

	pfn = phys_to_pfn_t(page_to_phys(pg), PFN_DEV | PFN_MAP);
	rc = vm_insert_mixed(vmf->vma, vmf->address, pfn);

	mutex_unlock(&pv->mutex);

	if (rc == -ENOMEM)
		return VM_FAULT_OOM;
	if (rc < 0 && rc != -EBUSY)
		return VM_FAULT_SIGBUS;

	return VM_FAULT_NOPAGE;
}

const struct vm_operations_struct p2pmem_vmops = {
	.open = p2pmem_vma_open,
	.close = p2pmem_vma_close,
	.fault = p2pmem_vma_fault,
};

static int p2pmem_open(struct inode *inode, struct file *filp)
{
	struct p2pmem_dev *p;

	p = container_of(inode->i_cdev, struct p2pmem_dev, cdev);
	filp->private_data = p;
	p->inode = inode;

	return 0;
}

static int p2pmem_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct p2pmem_dev *p = filp->private_data;
	struct p2pmem_vma *pv;
	size_t nr_pages = (vma->vm_end - vma->vm_start) / PAGE_SIZE;

	if ((vma->vm_flags & VM_MAYSHARE) != VM_MAYSHARE) {
		dev_warn(&p->dev, "mmap failed: can't create private mapping\n");
		return -EINVAL;
	}

	dev_dbg(&p->dev, "Allocating mmap with %zd pages.\n", nr_pages);

	pv = kzalloc(sizeof(*pv) + sizeof(pv->used_pages[0]) * nr_pages,
		     GFP_KERNEL);
	if (!pv)
		return -ENOMEM;

	mutex_init(&pv->mutex);
	pv->nr_pages = nr_pages;
	pv->p2pmem_dev = p;
	atomic_set(&pv->mmap_count, 1);

	vma->vm_private_data = pv;
	vma->vm_ops = &p2pmem_vmops;
	vma->vm_flags |= VM_MIXEDMAP;

	return 0;
}

static const struct file_operations p2pmem_fops = {
	.owner = THIS_MODULE,
	.open = p2pmem_open,
	.mmap = p2pmem_mmap,
};

static void p2pmem_percpu_release(struct percpu_ref *ref)
{
	struct p2pmem_dev *p = container_of(ref, struct p2pmem_dev, ref);

	complete_all(&p->cmp);
}

static void p2pmem_percpu_exit(void *data)
{
	struct percpu_ref *ref = data;
	struct p2pmem_dev *p = container_of(ref, struct p2pmem_dev, ref);

	wait_for_completion(&p->cmp);
	percpu_ref_exit(ref);
}

static void p2pmem_percpu_kill(void *data)
{
	struct percpu_ref *ref = data;

	if (percpu_ref_is_dying(ref))
		return;

	percpu_ref_kill(ref);
}

static void p2pmem_release(struct device *dev)
{
	struct p2pmem_dev *p = to_p2pmem(dev);

	debugfs_remove_recursive(p->debugfs_root);

	if (p->pool)
		gen_pool_destroy(p->pool);

	kfree(p);
}

struct remove_callback {
	struct list_head list;
	void (*callback)(void *context);
	void *context;
};

static void p2pmem_remove(struct p2pmem_dev *p)
{
	struct remove_callback *remove_call, *tmp;
	struct vm_area_struct *vma;

	p->alive = false;
	list_for_each_entry_safe(remove_call, tmp, &p->remove_list, list)
		remove_call->callback(remove_call->context);

	if (!p->inode)
		return;

	unmap_mapping_range(p->inode->i_mapping, 0, 0, 1);

	i_mmap_lock_write(p->inode->i_mapping);
	vma_interval_tree_foreach(vma, &p->inode->i_mapping->i_mmap, 0,
				  ULONG_MAX) {
		p2pmem_vma_free_pages(vma);
	}
	i_mmap_unlock_write(p->inode->i_mapping);
}

/**
 * p2pmem_create() - create a new p2pmem device
 * @parent: the parent device to create it under
 *
 * Return value is a pointer to the new device or an ERR_PTR
 * on failure.
 */
struct p2pmem_dev *p2pmem_create(struct device *parent)
{
	struct p2pmem_dev *p;
	int nid = dev_to_node(parent);
	int rc;

	p = kzalloc_node(sizeof(*p), GFP_KERNEL, nid);
	if (!p)
		return ERR_PTR(-ENOMEM);

	init_completion(&p->cmp);
	mutex_init(&p->remove_mutex);
	INIT_LIST_HEAD(&p->remove_list);
	p->alive = true;

	device_initialize(&p->dev);
	p->dev.class = p2pmem_class;
	p->dev.parent = parent;
	p->dev.release = p2pmem_release;

	cdev_init(&p->cdev, &p2pmem_fops);
	p->cdev.owner = THIS_MODULE;
	p->cdev.kobj.parent = &p->dev.kobj;

	p->id = ida_simple_get(&p2pmem_ida, 0, 0, GFP_KERNEL);
	if (p->id < 0) {
		rc = p->id;
		goto err_free;
	}

	dev_set_name(&p->dev, "p2pmem%d", p->id);
	p->dev.devt = MKDEV(MAJOR(p2pmem_devt), p->id);

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

	if (p2pmem_debugfs_root) {
		p->debugfs_root = debugfs_create_dir(dev_name(&p->dev),
						     p2pmem_debugfs_root);
		if (p->debugfs_root)
			setup_debugfs(p);
	}

	rc = cdev_add(&p->cdev, p->dev.devt, 1);
	if (rc)
		goto err_id;

	rc = device_add(&p->dev);
	if (rc)
		goto err_cdev;

	dev_info(&p->dev, "registered");
	return p;

err_cdev:
	cdev_del(&p->cdev);
	p2pmem_remove(p);
err_id:
	ida_simple_remove(&p2pmem_ida, p->id);
err_free:
	put_device(&p->dev);
	return ERR_PTR(rc);
}
EXPORT_SYMBOL(p2pmem_create);

/**
 * p2pmem_unregister() - unregister a p2pmem device
 * @p: the device to unregister
 *
 * The device will remain until all users are done with it
 */
void p2pmem_unregister(struct p2pmem_dev *p)
{
	if (!p)
		return;

	dev_info(&p->dev, "unregistered");
	device_del(&p->dev);
	cdev_del(&p->cdev);
	p2pmem_remove(p);
	ida_simple_remove(&p2pmem_ida, p->id);
	put_device(&p->dev);
}
EXPORT_SYMBOL(p2pmem_unregister);

/**
 * p2pmem_add_resource() - add memory for use as p2pmem to the device
 * @p: the device to add the memory to
 * @res: resource describing the memory
 *
 * The memory will be given ZONE_DEVICE struct pages so that it may
 * be used with any dma request.
 */
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

#ifdef CONFIG_PCI

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

/**
 * p2pmem_add_pci_region() - request and add an entire PCI region to the
 *	specified p2pmem device
 * @p: the device to add the memory to
 * @pdev: pci device to register the bar from
 * @bar: the bar number to add
 *
 * The memory will be given ZONE_DEVICE struct pages so that it may
 * be used with any dma request.
 */
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

#endif

/**
 * p2pmem_alloc() - allocate some p2p memory
 * @p: the device to allocate memory from
 * @size: number of bytes to allocate
 *
 * Returns the allocated memory or NULL on error
 */
void *p2pmem_alloc(struct p2pmem_dev *p, size_t size)
{
	if (!p->alive)
		return NULL;

	return (void *)gen_pool_alloc(p->pool, size);
}
EXPORT_SYMBOL(p2pmem_alloc);

/**
 * p2pmem_free() - free allocated p2p memory
 * @p: the device the memory was allocated from
 * @addr: address of the memory that was allocated
 * @size: number of bytes that was allocated
 */
void p2pmem_free(struct p2pmem_dev *p, void *addr, size_t size)
{
	gen_pool_free(p->pool, (unsigned long)addr, size);
}
EXPORT_SYMBOL(p2pmem_free);

static struct device *find_parent_pci_dev(struct device *dev)
{
	while (dev) {
		if (dev_is_pci(dev))
			return dev;

		dev = dev->parent;
	}

	return NULL;
}

/*
 * If a device is behind a switch, we try to find the upstream bridge
 * port of the switch. This requires two calls to pci_upstream_bridge:
 * one for the upstream port on the switch, one on the upstream port
 * for the next level in the hierarchy. Because of this, devices connected
 * to the root port will be rejected.
 */
static struct pci_dev *get_upstream_switch_port(struct device *dev)
{
	struct device *dpci;
	struct pci_dev *pci;

	dpci = find_parent_pci_dev(dev);
	if (!dpci)
		return NULL;

	pci = pci_upstream_bridge(to_pci_dev(dpci));
	if (!pci)
		return NULL;

	return pci_upstream_bridge(pci);
}

static int upstream_bridges_match(struct device *p2pmem,
				  const void *data)
{
	struct device * const *dma_devices = data;
	struct pci_dev *p2p_up;
	struct pci_dev *dma_up;

	if (!to_p2pmem(p2pmem)->alive)
		return false;

	p2p_up = get_upstream_switch_port(p2pmem);
	if (!p2p_up) {
		dev_warn(p2pmem, "p2pmem is not behind a pci switch");
		return false;
	}

	while (*dma_devices) {
		dma_up = get_upstream_switch_port(*dma_devices);

		if (!dma_up) {
			dev_dbg(p2pmem, "%s is not a pci device behind a switch",
				dev_name(*dma_devices));
			return false;
		}

		if (p2p_up != dma_up) {
			dev_dbg(p2pmem,
				"%s does not reside on the same upstream bridge",
				dev_name(*dma_devices));
			return false;
		}

		dev_dbg(p2pmem, "%s is compatible", dev_name(*dma_devices));
		dma_devices++;
	}

	return true;
}

/**
 * p2pmem_find_compat() - find a p2pmem device compatible with the
 *	specified devices
 * @dma_devices: a null terminated array of device pointers which
 *	all must be compatible with the returned p2pmem device
 * @remove_callback: this callback will be called if the p2pmem
 *	device is removed.
 *
 * For now, we only support cases where all the devices that
 * will transfer to the p2pmem device are on the same switch.
 * This cuts out cases that may work but is safest for the user.
 * We also do not presently support cases where two devices
 * are behind multiple levels of switches even though this would
 * likely work fine.
 *
 * Future work could be done to whitelist root ports that are known
 * to be good and support many levels of switches. Additionally,
 * it would make sense to choose the topographically closest p2pmem
 * for a given setup. (Presently we only return the first that matches.)
 *
 * Returns a pointer to the p2pmem device with the reference taken
 * (use p2pmem_put to return the reference) or NULL if no compatible
 * p2pmem device is found.
 */
struct p2pmem_dev *p2pmem_find_compat(struct device **dma_devices,
				      void (*remove_callback)(void *context),
				      void *context)
{
	struct device *dev;
	struct p2pmem_dev *p;
	struct remove_callback *remove_call;

	dev = class_find_device(p2pmem_class, NULL, dma_devices,
				upstream_bridges_match);

	if (!dev)
		return NULL;

	p = to_p2pmem(dev);
	mutex_lock(&p->remove_mutex);

	if (!p->alive) {
		p = NULL;
		goto out;
	}

	remove_call = kzalloc(sizeof(*remove_call), GFP_KERNEL);
	remove_call->callback = remove_callback;
	remove_call->context = context;
	INIT_LIST_HEAD(&remove_call->list);
	list_add(&remove_call->list, &p->remove_list);

out:
	mutex_unlock(&p->remove_mutex);
	return p;
}
EXPORT_SYMBOL(p2pmem_find_compat);

/**
 * p2pmem_put() - decrement a p2pmem device reference
 * @p: p2pmem device to return
 * @data: data pointer that was passed to p2pmem_find_compat
 *
 * Dereference and free (if last) the device's reference counter.
 * It's safe to pass a NULL pointer to this function.
 */
void p2pmem_put(struct p2pmem_dev *p, void *context)
{
	struct remove_callback *remove_call;

	if (!p)
		return;

	mutex_lock(&p->remove_mutex);

	list_for_each_entry(remove_call, &p->remove_list, list) {
		if (remove_call->context != context)
			continue;

		list_del(&remove_call->list);
		kfree(remove_call);
		break;
	}

	mutex_unlock(&p->remove_mutex);
	put_device(&p->dev);
}
EXPORT_SYMBOL(p2pmem_put);

static int __init p2pmem_init(void)
{
	int rc;

	p2pmem_class = class_create(THIS_MODULE, "p2pmem");
	if (IS_ERR(p2pmem_class))
		return PTR_ERR(p2pmem_class);

	rc = alloc_chrdev_region(&p2pmem_devt, 0, max_devices, "iopmemc");
	if (rc)
		goto err_chrdev;

	p2pmem_debugfs_root = debugfs_create_dir("p2pmem", NULL);
	if (!p2pmem_debugfs_root)
		pr_info("could not create debugfs entry, continuing\n");

	return 0;

err_chrdev:
	class_destroy(p2pmem_class);
	return rc;
}
subsys_initcall(p2pmem_init);

static void __exit p2pmem_exit(void)
{
	debugfs_remove_recursive(p2pmem_debugfs_root);
	unregister_chrdev_region(p2pmem_devt, max_devices);
	class_destroy(p2pmem_class);

	pr_info(KBUILD_MODNAME ": unloaded.\n");
}
module_exit(p2pmem_exit);
