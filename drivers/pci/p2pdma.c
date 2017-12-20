/* SPDX-License-Identifier: GPL-2.0 */
/*
 * PCI Peer 2 Peer DMA support.
 *
 * Copyright (c) 2016-2017, Microsemi Corporation
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

#include <linux/pci-p2pdma.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/genalloc.h>
#include <linux/memremap.h>
#include <linux/percpu-refcount.h>

struct pci_p2pdma {
	struct percpu_ref devmap_ref;
	struct completion devmap_ref_done;
	struct gen_pool *pool;
	bool published;
};

static ssize_t size_show(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	size_t size = 0;

	if (pdev->p2pdma->pool)
		size = gen_pool_size(pdev->p2pdma->pool);

	return snprintf(buf, PAGE_SIZE, "%zd\n", size);
}
static DEVICE_ATTR_RO(size);

static ssize_t available_show(struct device *dev, struct device_attribute *attr,
			      char *buf)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	size_t avail = 0;

	if (pdev->p2pdma->pool)
		avail = gen_pool_avail(pdev->p2pdma->pool);

	return snprintf(buf, PAGE_SIZE, "%zd\n", avail);
}
static DEVICE_ATTR_RO(available);

static ssize_t published_show(struct device *dev, struct device_attribute *attr,
			      char *buf)
{
	struct pci_dev *pdev = to_pci_dev(dev);

	return snprintf(buf, PAGE_SIZE, "%d\n", pdev->p2pdma->published);
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

static void pci_p2pdma_percpu_release(struct percpu_ref *ref)
{
	struct pci_p2pdma *p2p =
		container_of(ref, struct pci_p2pdma, devmap_ref);

	complete_all(&p2p->devmap_ref_done);
}

static void pci_p2pdma_percpu_kill(void *data)
{
	struct percpu_ref *ref = data;

	if (percpu_ref_is_dying(ref))
		return;

	percpu_ref_kill(ref);
}

static void pci_p2pdma_release(void *data)
{
	struct pci_dev *pdev = data;

	wait_for_completion(&pdev->p2pdma->devmap_ref_done);
	percpu_ref_exit(&pdev->p2pdma->devmap_ref);

	gen_pool_destroy(pdev->p2pdma->pool);
	sysfs_remove_group(&pdev->dev.kobj, &p2pmem_group);
	pdev->p2pdma = NULL;
}

static int pci_p2pdma_setup(struct pci_dev *pdev)
{
	int error = -ENOMEM;
	struct pci_p2pdma *p2p;

	p2p = devm_kzalloc(&pdev->dev, sizeof(*p2p), GFP_KERNEL);
	if (!p2p)
		return -ENOMEM;

	p2p->pool = gen_pool_create(PAGE_SHIFT, dev_to_node(&pdev->dev));
	if (!p2p->pool)
		goto out;

	init_completion(&p2p->devmap_ref_done);
	error = percpu_ref_init(&p2p->devmap_ref,
			pci_p2pdma_percpu_release, 0, GFP_KERNEL);
	if (error)
		goto out_pool_destroy;

	percpu_ref_switch_to_atomic_sync(&p2p->devmap_ref);

	error = devm_add_action_or_reset(&pdev->dev, pci_p2pdma_release, pdev);
	if (error)
		goto out_pool_destroy;

	error = sysfs_create_group(&pdev->dev.kobj, &p2pmem_group);

	pdev->p2pdma = p2p;

	return 0;

out_pool_destroy:
	gen_pool_destroy(p2p->pool);
out:
	devm_kfree(&pdev->dev, p2p);
	return error;
}

/**
 * pci_p2pdma_add_resource - add memory for use as p2p memory
 * @pci: the device to add the memory to
 * @bar: PCI BAR to add
 * @size: size of the memory to add, may be zero to use the whole BAR
 * @offset: offset into the PCI BAR
 *
 * The memory will be given ZONE_DEVICE struct pages so that it may
 * be used with any dma request.
 */
int pci_p2pdma_add_resource(struct pci_dev *pdev, int bar, size_t size,
			    u64 offset)
{
	struct dev_pagemap *pgmap;
	void *addr;
	int error;

	if (!(pci_resource_flags(pdev, bar) & IORESOURCE_MEM))
		return -EINVAL;

	if (offset >= pci_resource_len(pdev, bar))
		return -EINVAL;

	if (!size)
		size = pci_resource_len(pdev, bar) - offset;

	if (size + offset > pci_resource_len(pdev, bar))
		return -EINVAL;

	if (!pdev->p2pdma) {
		error = pci_p2pdma_setup(pdev);
		if (error)
			return error;
	}

	pgmap = devm_kzalloc(&pdev->dev, sizeof(*pgmap), GFP_KERNEL);
	if (!pgmap)
		return -ENOMEM;

	pgmap->res.start = pci_resource_start(pdev, bar) + offset;
	pgmap->res.end = pgmap->res.start + size - 1;
	pgmap->res.flags = pci_resource_flags(pdev, bar);
	pgmap->ref = &pdev->p2pdma->devmap_ref;
	pgmap->type = MEMORY_DEVICE_PCI_P2PDMA;
	pgmap->pci_p2pdma_bus_offset = pci_bus_address(pdev, bar) -
		pci_resource_start(pdev, bar);

	addr = devm_memremap_pages(&pdev->dev, pgmap);
	if (IS_ERR(addr))
		return PTR_ERR(addr);

	error = gen_pool_add_virt(pdev->p2pdma->pool, (uintptr_t)addr,
			pci_bus_address(pdev, bar) + offset,
			resource_size(&pgmap->res), dev_to_node(&pdev->dev));
	if (error)
		return error;

	error = devm_add_action_or_reset(&pdev->dev, pci_p2pdma_percpu_kill,
					  &pdev->p2pdma->devmap_ref);
	if (error)
		return error;

	dev_info(&pdev->dev, "added peer-to-peer DMA memory %pR\n",
		 &pgmap->res);

	return 0;
}
EXPORT_SYMBOL_GPL(pci_p2pdma_add_resource);

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
static struct pci_dev *get_upstream_bridge_port(struct pci_dev *pdev)
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

static bool __upstream_bridges_match(struct pci_dev *upstream,
				     struct pci_dev *client)
{
	struct pci_dev *dma_up;
	bool ret = true;

	dma_up = get_upstream_bridge_port(client);

	if (!dma_up) {
		dev_dbg(&client->dev, "not a PCI device behind a bridge\n");
		ret = false;
		goto out;
	}

	if (upstream != dma_up) {
		dev_dbg(&client->dev,
			"does not reside on the same upstream bridge\n");
		ret = false;
		goto out;
	}

out:
	pci_dev_put(dma_up);
	return ret;
}

static bool upstream_bridges_match(struct pci_dev *pdev,
				   struct pci_dev *client)
{
	struct pci_dev *upstream;
	bool ret;

	upstream = get_upstream_bridge_port(pdev);
	if (!upstream) {
		dev_warn(&pdev->dev, "not behind a PCI bridge\n");
		return false;
	}

	ret = __upstream_bridges_match(upstream, client);

	pci_dev_put(upstream);

	return ret;
}

struct pci_p2pdma_client {
	struct list_head list;
	struct pci_dev *client;
	struct pci_dev *p2pdma;
};

/**
 * pci_p2pdma_add_client - allocate a new element in a client device list
 * @head: list head of p2pdma clients
 * @dev: device to add to the list
 *
 * This adds @dev to a list of clients used by a p2pdma device.
 * This list should be passed to p2pmem_find(). Once p2pmem_find() has
 * been called successfully, the list will be bound to a specific p2pdma
 * device and new clients can only be added to the list if they are
 * supported by that p2pdma device.
 *
 * The caller is expected to have a lock which protects @head as necessary
 * so that none of the pci_p2p functions can be called concurrently
 * on that list.
 *
 * Returns 0 if the client was successfully added.
 */
int pci_p2pdma_add_client(struct list_head *head, struct device *dev)
{
	struct pci_p2pdma_client *item, *new_item;
	struct pci_dev *p2pdma = NULL;
	struct pci_dev *client;
	int ret;

	if (IS_ENABLED(CONFIG_DMA_VIRT_OPS) && dev->dma_ops == &dma_virt_ops) {
		dev_warn(dev,
			 "cannot be used for peer-to-peer DMA because the driver makes use of dma_virt_ops\n");
		return -ENODEV;
	}


	client = find_parent_pci_dev(dev);
	if (!client) {
		dev_warn(dev,
			 "cannot be used for peer-to-peer DMA as it is not a PCI device\n");
		return -ENODEV;
	}

	item = list_first_entry_or_null(head, struct pci_p2pdma_client, list);
	if (item && item->p2pdma) {
		p2pdma = item->p2pdma;

		if (!upstream_bridges_match(p2pdma, client)) {
			ret = -EXDEV;
			goto put_client;
		}
	}

	new_item = kzalloc(sizeof(*new_item), GFP_KERNEL);
	if (!new_item) {
		ret = -ENOMEM;
		goto put_client;
	}

	new_item->client = client;
	new_item->p2pdma = pci_dev_get(p2pdma);

	list_add_tail(&new_item->list, head);

	return 0;

put_client:
	pci_dev_put(client);
	return ret;
}
EXPORT_SYMBOL_GPL(pci_p2pdma_add_client);

static void pci_p2pdma_client_free(struct pci_p2pdma_client *item)
{
	list_del(&item->list);
	pci_dev_put(item->client);
	pci_dev_put(item->p2pdma);
	kfree(item);
}

/**
 * pci_p2pdma_remove_client - remove and free a new p2pdma client
 * @head: list head of p2pdma clients
 * @dev: device to remove from the list
 *
 * This removes @dev from a list of clients used by a p2pdma device.
 * The caller is expected to have a lock which protects @head as necessary
 * so that none of the pci_p2p functions can be called concurrently
 * on that list.
 */
void pci_p2pdma_remove_client(struct list_head *head, struct device *dev)
{
	struct pci_p2pdma_client *pos, *tmp;
	struct pci_dev *pdev;

	pdev = find_parent_pci_dev(dev);
	if (!pdev)
		return;

	list_for_each_entry_safe(pos, tmp, head, list) {
		if (pos->client != pdev)
			continue;

		pci_p2pdma_client_free(pos);
	}

	pci_dev_put(pdev);
}
EXPORT_SYMBOL_GPL(pci_p2pdma_remove_client);

/**
 * pci_p2pdma_client_list_free - free an entire list of p2pdma clients
 * @head: list head of p2pdma clients
 *
 * This removes all devices in a list of clients used by a p2pdma device.
 * The caller is expected to have a lock which protects @head as necessary
 * so that none of the pci_p2pdma functions can be called concurrently
 * on that list.
 */
void pci_p2pdma_client_list_free(struct list_head *head)
{
	struct pci_p2pdma_client *pos, *tmp;

	list_for_each_entry_safe(pos, tmp, head, list)
		pci_p2pdma_client_free(pos);
}
EXPORT_SYMBOL_GPL(pci_p2pdma_client_list_free);

static bool upstream_bridges_match_list(struct pci_dev *pdev,
					struct list_head *head)
{
	struct pci_p2pdma_client *pos;
	struct pci_dev *upstream;
	bool ret;

	upstream = get_upstream_bridge_port(pdev);
	if (!upstream) {
		dev_warn(&pdev->dev, "not behind a PCI bridge\n");
		return false;
	}

	list_for_each_entry(pos, head, list) {
		ret = __upstream_bridges_match(upstream, pos->client);
		if (!ret)
			break;
	}

	pci_dev_put(upstream);
	return ret;
}

/**
 * pci_p2pmem_find - find a peer-to-peer DMA memory device compatible with
 *	the specified list of clients
 * @dev: list of devices to check (NULL-terminated)
 *
 * For now, we only support cases where the devices that will transfer to the
 * p2pmem device are behind the same bridge. This cuts out cases that may work but
 * is safest for the user.
 *
 * Returns a pointer to the PCI device with a reference taken (use pci_dev_put
 * to return the reference) or NULL if no compatible device is found.
 */
struct pci_dev *pci_p2pmem_find(struct list_head *clients)
{
	struct pci_dev *pdev = NULL;
	struct pci_p2pdma_client *pos;

	while ((pdev = pci_get_device(PCI_ANY_ID, PCI_ANY_ID, pdev))) {
		if (!pdev->p2pdma || !pdev->p2pdma->published)
			continue;

		if (!upstream_bridges_match_list(pdev, clients))
			continue;

		list_for_each_entry(pos, clients, list)
			pos->p2pdma = pdev;

		return pdev;
	}

	return NULL;
}
EXPORT_SYMBOL_GPL(pci_p2pmem_find);

/**
 * pci_alloc_p2p_mem - allocate peer-to-peer DMA memory
 * @pdev:	the device to allocate memory from
 * @size:	number of bytes to allocate
 *
 * Returns the allocated memory or NULL on error.
 */
void *pci_alloc_p2pmem(struct pci_dev *pdev, size_t size)
{
	void *ret;

	if (unlikely(!pdev->p2pdma))
		return NULL;

	if (unlikely(!percpu_ref_tryget_live(&pdev->p2pdma->devmap_ref)))
		return NULL;

	ret = (void *)(uintptr_t)gen_pool_alloc(pdev->p2pdma->pool, size);

	if (unlikely(!ret))
		percpu_ref_put(&pdev->p2pdma->devmap_ref);

	return ret;
}
EXPORT_SYMBOL_GPL(pci_alloc_p2pmem);

/**
 * pci_free_p2pmem - allocate peer-to-peer DMA memory
 * @pdev:	the device the memory was allocated from
 * @addr:	address of the memory that was allocated
 * @size:	number of bytes that was allocated
 */
void pci_free_p2pmem(struct pci_dev *pdev, void *addr, size_t size)
{
	gen_pool_free(pdev->p2pdma->pool, (uintptr_t)addr, size);
	percpu_ref_put(&pdev->p2pdma->devmap_ref);
}
EXPORT_SYMBOL_GPL(pci_free_p2pmem);

/**
 * pci_virt_to_bus - return the PCI bus address for a given virtual
 *	address obtained with pci_alloc_p2pmem
 * @pdev:	the device the memory was allocated from
 * @addr:	address of the memory that was allocated
 */
pci_bus_addr_t pci_p2pmem_virt_to_bus(struct pci_dev *pdev, void *addr)
{
	if (!addr)
		return 0;
	if (!pdev->p2pdma)
		return 0;

	/*
	 * Note: when we added the memory to the pool we used the PCI
	 * bus address as the physical address. So gen_pool_virt_to_phys()
	 * actually returns the bus address despite the misleading name.
	 */
	return gen_pool_virt_to_phys(pdev->p2pdma->pool, (unsigned long)addr);
}
EXPORT_SYMBOL_GPL(pci_p2pmem_virt_to_bus);

/**
 * pci_p2pmem_alloc_sgl - allocate peer-to-peer DMA memory in an scatterlist
 * @pdev:	the device to allocate memory from
 * @sgl:	the allocated scatterlist
 * @nents:      the number of SG entries in the list
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

	sg_init_table(sg, 1);

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
 * pci_p2pmem_free_sgl - free a scatterlist  allocated by pci_p2pmem_alloc_sgl
 * @pdev:	the device to allocate memory from
 * @sgl:	the allocated scatterlist
 * @nents:      the number of SG entries in the list
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
 * pci_p2pmem_publish - publish the peer-to-peer DMA memory for use by
 *	other devices with pci_p2pmem_find
 * @pdev:	the device with peer-to-peer DMA memory to publish
 * @publish:	set to true to publish the memory, false to unpublish it
 */
void pci_p2pmem_publish(struct pci_dev *pdev, bool publish)
{
	if (publish && !pdev->p2pdma)
		return;

	pdev->p2pdma->published = publish;
}
EXPORT_SYMBOL_GPL(pci_p2pmem_publish);

/*
 * pci_p2pdma_map_sg - map a PCI peer-to-peer sg for DMA
 * @dev:        device doing the DMA request
 * @sg:		scatter list to map
 * @nents:	elements in the scatterlist
 * @dir:        DMA direction
 *
 * Returns the number of SG entries mapped
 */
int pci_p2pdma_map_sg(struct device *dev, struct scatterlist *sg, int nents,
		      enum dma_data_direction dir)
{
	struct dev_pagemap *pgmap;
	struct scatterlist *s;
	phys_addr_t paddr;
	int i;

	/*
	 * p2pdma mappings are not compatible with devices that use
	 * dma_virt_ops.
	 */
	if (IS_ENABLED(CONFIG_DMA_VIRT_OPS) && dev->dma_ops == &dma_virt_ops)
		return 0;

	for_each_sg(sg, s, nents, i) {
		pgmap = sg_page(s)->pgmap;
		paddr = sg_phys(s);

		s->dma_address = paddr - pgmap->pci_p2pdma_bus_offset;
		sg_dma_len(s) = s->length;
	}

	return nents;
}
EXPORT_SYMBOL_GPL(pci_p2pdma_map_sg);

/**
 * pci_p2pdma_unmap_sg - unmap a PCI peer-to-peer sg for DMA
 * @dev:        device doing the DMA request
 * @sg:		scatter list to map
 * @nents:	elements in the scatterlist
 * @dir:        DMA direction
 */
void pci_p2pdma_unmap_sg(struct device *dev, struct scatterlist *sg, int nents,
			 enum dma_data_direction dir)
{
	struct scatterlist *s;
	int i;

	for_each_sg(sg, s, nents, i)
		dma_mark_clean(phys_to_virt(sg_phys(s)), sg_dma_len(s));
}
EXPORT_SYMBOL_GPL(pci_p2pdma_unmap_sg);
