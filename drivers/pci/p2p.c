/*
 * Peer 2 Peer Memory support.
 *
 * Copyright (c) 2016, Microsemi Corporation
 * Copyright (c) 2017, Christoph Hellwig.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#include <linux/pci.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/genalloc.h>
#include <linux/memremap.h>

struct pci_p2pmem_pagemap {
	struct dev_pagemap pgmap;
	pci_bus_addr_t bus_offset;
};

struct pci_p2pmem_pagemap *to_pci_p2pmem_pagemap(struct dev_pagemap *pgmap)
{
	return container_of(pgmap, struct pci_p2pmem_pagemap, pgmap);
}

static ssize_t size_show(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	size_t size = 0;

	if (pdev->p2p_pool)
		size = gen_pool_size(pdev->p2p_pool);

	return snprintf(buf, PAGE_SIZE, "%zd\n", size);
}
static DEVICE_ATTR_RO(size);

static ssize_t available_show(struct device *dev, struct device_attribute *attr,
			      char *buf)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	size_t avail = 0;

	if (pdev->p2p_pool)
		avail = gen_pool_avail(pdev->p2p_pool);

	return snprintf(buf, PAGE_SIZE, "%zd\n", avail);
}
static DEVICE_ATTR_RO(available);

static ssize_t published_show(struct device *dev, struct device_attribute *attr,
			      char *buf)
{
	struct pci_dev *pdev = to_pci_dev(dev);

	return snprintf(buf, PAGE_SIZE, "%d\n", pdev->p2p_published);
}
static DEVICE_ATTR_RO(published);

static struct attribute *p2pmem_attrs[] = {
	&dev_attr_size.attr,
	&dev_attr_available.attr,
	&dev_attr_published.attr,
	NULL,
};

static const struct attribute_group p2pmem_group = {
	.attrs = p2pmem_attrs,
	.name = "p2pmem",
};

static void pci_p2pmem_percpu_release(struct percpu_ref *ref)
{
	struct pci_dev *pdev =
		container_of(ref, struct pci_dev, p2p_devmap_ref);

	complete_all(&pdev->p2p_devmap_ref_done);
}

static void pci_p2pmem_percpu_exit(void *data)
{
	struct percpu_ref *ref = data;
	struct pci_dev *pdev =
		container_of(ref, struct pci_dev, p2p_devmap_ref);

	wait_for_completion(&pdev->p2p_devmap_ref_done);
	percpu_ref_exit(ref);
}

static void pci_p2pmem_percpu_kill(void *data)
{
	struct percpu_ref *ref = data;

	if (percpu_ref_is_dying(ref))
		return;
	percpu_ref_kill(ref);
}

void pci_p2pmem_release(struct pci_dev *pdev)
{
	sysfs_remove_group(&pdev->dev.kobj, &p2pmem_group);

	if (pdev->p2p_pool)
		gen_pool_destroy(pdev->p2p_pool);
}

static int pci_p2pmem_setup(struct pci_dev *pdev)
{
	int error = -ENOMEM;

	pdev->p2p_pool = gen_pool_create(PAGE_SHIFT, dev_to_node(&pdev->dev));
	if (!pdev->p2p_pool)
		goto out;

	init_completion(&pdev->p2p_devmap_ref_done);
	error = percpu_ref_init(&pdev->p2p_devmap_ref,
			pci_p2pmem_percpu_release, 0, GFP_KERNEL);
	if (error)
		goto out_pool_destroy;

	error = devm_add_action_or_reset(&pdev->dev, pci_p2pmem_percpu_exit,
			&pdev->p2p_devmap_ref);
	if (error)
		goto out_pool_destroy;

	if (sysfs_create_group(&pdev->dev.kobj, &p2pmem_group))
		dev_warn(&pdev->dev, "failed to create p2p sysfs group\n");

	return 0;

out_pool_destroy:
	gen_pool_destroy(pdev->p2p_pool);
out:
	return error;
}

/**
 * pci_p2pmem_add_resource - add memory for use as p2p memory
 * @pci: the device to add the memory to
 * @bar: PCI bar to add
 * @size: size of the memory to add, may be zero to use the whole bar
 * @offset: offset into the PCI bar
 *
 * The memory will be given ZONE_DEVICE struct pages so that it may
 * be used with any dma request.
 */
int pci_p2pmem_add_resource(struct pci_dev *pdev, int bar, size_t size,
			    u64 offset)
{
	struct pci_p2pmem_pagemap *p2pmap;
	void *addr;
	int error;

	if (WARN_ON(offset >= pci_resource_len(pdev, bar)))
		return -EINVAL;

	if (!size)
		size = pci_resource_len(pdev, bar) - offset;

	if (WARN_ON(size + offset > pci_resource_len(pdev, bar)))
		return -EINVAL;

	if (!pdev->p2p_pool) {
		error = pci_p2pmem_setup(pdev);
		if (error)
			return error;
	}

	p2pmap = devm_kzalloc(&pdev->dev, sizeof(*p2pmap), GFP_KERNEL);
	if (!p2pmap)
		return -ENOMEM;

	p2pmap->pgmap.res.start = pci_resource_start(pdev, bar) + offset;
	p2pmap->pgmap.res.end = p2pmap->pgmap.res.start + size;
	p2pmap->pgmap.ref = &pdev->p2p_devmap_ref;
	p2pmap->pgmap.type = MEMORY_DEVICE_PCI_P2P;
	p2pmap->bus_offset = pci_bus_address(pdev, bar) -
		pci_resource_start(pdev, bar);

	addr = devm_memremap_pages(&pdev->dev, &p2pmap->pgmap);
	if (IS_ERR(addr))
		return PTR_ERR(addr);

	error = gen_pool_add_virt(pdev->p2p_pool, (uintptr_t)addr,
			pci_bus_address(pdev, bar) + offset,
			resource_size(&p2pmap->pgmap.res),
			dev_to_node(&pdev->dev));
	if (error)
		return error;

	return devm_add_action_or_reset(&pdev->dev, pci_p2pmem_percpu_kill,
			&pdev->p2p_devmap_ref);
}
EXPORT_SYMBOL_GPL(pci_p2pmem_add_resource);

static struct pci_dev *find_parent_pci_dev(struct device *dev)
{
	struct device *parent;

	dev = get_device(dev);

	while (dev) {
		if (dev_is_pci(dev))
			return to_pci_dev(dev);

		parent = get_device(dev->parent);
		put_device(dev);
		dev = parent;
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
static struct pci_dev *get_upstream_switch_port(struct pci_dev *pdev)
{
	struct pci_dev *up1, *up2;

	if (!pdev)
		return NULL;

	up1 = pci_dev_get(pci_upstream_bridge(pdev));
	if (!up1)
		return NULL;

	up2 = pci_dev_get(pci_upstream_bridge(up1));
	pci_dev_put(up1);

	return up2;
}

static int upstream_bridges_match(struct pci_dev *pdev, struct device **devs)
{
	struct pci_dev *p2p_up;
	struct pci_dev *dma_up;
	struct pci_dev *parent;
	bool ret = true;

	p2p_up = get_upstream_switch_port(pdev);
	if (!p2p_up) {
		dev_warn(&pdev->dev, "not behind a pci switch\n");
		return false;
	}

	for ( ; *devs; devs++) {
		parent = find_parent_pci_dev(*devs);
		dma_up = get_upstream_switch_port(parent);
		pci_dev_put(parent);

		if (!dma_up) {
			dev_dbg(*devs, "not a pci device behind a switch\n");
			pci_dev_put(dma_up);
			ret = false;
			goto out;
		}

		if (p2p_up != dma_up) {
			dev_dbg(&pdev->dev,
				"%s does not reside on the same upstream bridge\n",
				dev_name(*devs));
			pci_dev_put(dma_up);
			ret = false;
			goto out;
		}

		pci_dev_put(dma_up);
	}

out:
	pci_dev_put(p2p_up);
	return ret;
}

/**
 * pci_p2pmem_find - find a p2p mem device compatible with the specified device
 * @dev: list of device to check (NULL-terminated)
 *
 * For now, we only support cases where the devices that will transfer to the
 * p2pmem device are on the same switch.  This cuts out cases that may work but
 * is safest for the user.
 *
 * Returns a pointer to the PCI device with a reference taken (use pci_dev_put
 * to return the reference) or NULL if no compatible device is found.
 */
struct pci_dev *pci_p2pmem_find(struct device **devices)
{
	struct pci_dev *pdev = NULL;

	while ((pdev = pci_get_device(PCI_ANY_ID, PCI_ANY_ID, pdev))) {
		if (!pdev->p2p_published)
			continue;

		if (upstream_bridges_match(pdev, devices))
			return pdev;
	}

	return NULL;
}
EXPORT_SYMBOL_GPL(pci_p2pmem_find);

/**
 * pci_alloc_p2p_mem - allocate p2p memory
 * @pdev:	the device to allocate memory from
 * @size:	number of bytes to allocate
 *
 * Returns the allocated memory or NULL on error.
 */
void *pci_alloc_p2pmem(struct pci_dev *pdev, size_t size)
{
	return (void *)(uintptr_t)gen_pool_alloc(pdev->p2p_pool, size);
}
EXPORT_SYMBOL_GPL(pci_alloc_p2pmem);

/**
 * pci_free_p2pmem - allocate p2p memory
 * @pdev:	the device the memory was allocated from
 * @addr:	address of the memory that was allocated
 * @size:	number of bytes that was allocated
 */
void pci_free_p2pmem(struct pci_dev *pdev, void *addr, size_t size)
{
	gen_pool_free(pdev->p2p_pool, (uintptr_t)addr, size);
}
EXPORT_SYMBOL_GPL(pci_free_p2pmem);

/**
 * pci_virt_to_bus - return the pci bus address for a given virtual
 *	address obtained with pci_alloc_p2pmem
 * @pdev:	the device the memory was allocated from
 * @addr:	address of the memory that was allocated
 */
pci_bus_addr_t pci_p2pmem_virt_to_bus(struct pci_dev *pdev, void *addr)
{
	if (!addr)
		return 0;

	return gen_pool_virt_to_phys(pdev->p2p_pool, (unsigned long)addr);
}
EXPORT_SYMBOL_GPL(pci_p2pmem_virt_to_bus);

/**
 * pci_p2pmem_alloc_sgl - allocate p2p memory in an sgl
 * @pdev:	the device to allocate memory from
 * @sgl:	the allocated sgl
 * @nents:      the number of sgs in the list
 * @length:     number of bytes to allocate
 *
 * Returns 0 on success
 */
int pci_p2pmem_alloc_sgl(struct pci_dev *pdev, struct scatterlist **sgl,
			 unsigned int *nents, u32 length)
{
	struct scatterlist *sg;
	void *addr;

	sg = kzalloc(sizeof(*sg), GFP_KERNEL);
	if (!sg)
		return -ENOMEM;

	sg_init_p2p_table(sg, 1);

	addr = pci_alloc_p2pmem(pdev, length);
	if (!addr)
		goto out_free_sg;

	sg_set_buf(sg, addr, length);
	*sgl = sg;
	*nents = 1;
	return 0;

out_free_sg:
	kfree(sg);
	return -ENOMEM;
}
EXPORT_SYMBOL_GPL(pci_p2pmem_alloc_sgl);

/**
 * pci_p2pmem_free_sgl - free an sgl allocated by pci_p2pmem_alloc_sgl
 * @pdev:	the device to allocate memory from
 * @sgl:	the allocated sgl
 * @nents:      the number of sgs in the list
 */
void pci_p2pmem_free_sgl(struct pci_dev *pdev, struct scatterlist *sgl,
			 unsigned int nents)
{
	struct scatterlist *sg;
	int count;

	if (!sgl || !nents)
		return;

	for_each_sg(sgl, sg, nents, count)
		pci_free_p2pmem(pdev, sg_virt(sg), sg->length);
	kfree(sgl);
}
EXPORT_SYMBOL_GPL(pci_p2pmem_free_sgl);

/**
 * pci_p2pmem_publish - publish the p2p memory for use by other devices
 *	with pci_p2pmem_find
 * @pdev:	the device with p2p memory to publish
 * @publish:	set to true to publish the memory, false to unpublish it
 */
void pci_p2pmem_publish(struct pci_dev *pdev, bool publish)
{
	if (WARN_ON(publish && !pdev->p2p_pool))
		return;

	pdev->p2p_published = publish;
}
EXPORT_SYMBOL_GPL(pci_p2pmem_publish);

/*
 * pci_p2pmem_map_sg - map a pci p2p sg for dma
 * @sg:		scatter list to map
 * @nents:	elements in the scatter list
 *
 * Returns the number of sgls mapped
 */
int pci_p2pmem_map_sg(struct scatterlist *sg, int nents)
{
	struct pci_p2pmem_pagemap *p2pmap;
	struct scatterlist *s;
	phys_addr_t paddr;
	int i;

	for_each_sg(sg, s, nents, i) {
		p2pmap = to_pci_p2pmem_pagemap(sg_page(s)->pgmap);
		paddr = sg_phys(s);

		s->dma_address = paddr - p2pmap->bus_offset;
		sg_dma_len(s) = s->length;
	}

	return nents;
}
EXPORT_SYMBOL_GPL(pci_p2pmem_map_sg);

/**
 * pci_p2pmem_unmap_sg - unmap a pci p2p sg for dma
 * @sg:		scatter list to map
 * @nents:	elements in the scatter list
 */
void pci_p2pmem_unmap_sg(struct scatterlist *sg, int nents)
{
	struct scatterlist *s;
	int i;

	for_each_sg(sg, s, nents, i)
		dma_mark_clean(phys_to_virt(sg_phys(s)), sg_dma_len(s));
}
EXPORT_SYMBOL_GPL(pci_p2pmem_unmap_sg);
