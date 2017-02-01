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

#ifndef __P2PMEM_H__
#define __P2PMEM_H__

#include <linux/device.h>
#include <linux/pci.h>

struct p2pmem_dev {
	struct device dev;
	int id;

	struct percpu_ref ref;
	struct completion cmp;
	struct gen_pool *pool;
};

#ifdef CONFIG_P2PMEM

struct p2pmem_dev *p2pmem_create(struct device *parent);
void p2pmem_unregister(struct p2pmem_dev *p);

int p2pmem_add_resource(struct p2pmem_dev *p, struct resource *res);

#ifdef CONFIG_PCI
int p2pmem_add_pci_region(struct p2pmem_dev *p, struct pci_dev *pdev, int bar);
#endif

void *p2pmem_alloc(struct p2pmem_dev *p, size_t size);
void p2pmem_free(struct p2pmem_dev *p, void *addr, size_t size);

struct p2pmem_dev *p2pmem_find_compat(struct device **dma_devices);
void p2pmem_put(struct p2pmem_dev *p);

#else

static inline void *p2pmem_create(struct device *parent)
{
	return NULL;
}

static inline void p2pmem_unregister(struct p2pmem_dev *p)
{
}

static inline int p2pmem_add_resource(struct p2pmem_dev *p,
				      struct resource *res)
{
	return -ENODEV;
}

static inline int p2pmem_add_pci_region(struct p2pmem_dev *p,
					struct pci_dev *pdev, int bar)
{
	return -ENODEV;
}

static inline void *p2pmem_alloc(struct p2pmem_dev *p, size_t size)
{
	return NULL;
}

static inline void p2pmem_free(struct p2pmem_dev *p, void *addr, size_t size)
{
}

static inline struct p2pmem_dev *p2pmem_find_compat(struct device **dma_devs)
{
	return NULL;
}

static inline void p2pmem_put(struct p2pmem_dev *p)
{
}

#endif

static inline struct page *p2pmem_alloc_page(struct p2pmem_dev *p)
{
	struct page *pg = p2pmem_alloc(p, PAGE_SIZE);

	if (pg)
		return virt_to_page(pg);

	return NULL;
}

static inline void p2pmem_free_page(struct p2pmem_dev *p, struct page *pg)
{
	p2pmem_free(p, page_to_virt(pg), PAGE_SIZE);
}

#endif
