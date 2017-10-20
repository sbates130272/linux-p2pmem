/* SPDX-License-Identifier: GPL-2.0 */
/*
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

#ifndef _LINUX_PCI_P2PDMA_H
#define _LINUX_PCI_P2PDMA_H

#include <linux/pci.h>

struct block_device;
struct scatterlist;

#ifdef CONFIG_PCI_P2PDMA
int pci_p2pdma_add_resource(struct pci_dev *pdev, int bar, size_t size,
		u64 offset);
int pci_p2pdma_add_client(struct list_head *head, struct device *dev);
void pci_p2pdma_remove_client(struct list_head *head, struct device *dev);
void pci_p2pdma_client_list_free(struct list_head *head);
struct pci_dev *pci_p2pmem_find(struct list_head *clients);
void *pci_alloc_p2pmem(struct pci_dev *pdev, size_t size);
void pci_free_p2pmem(struct pci_dev *pdev, void *addr, size_t size);
pci_bus_addr_t pci_p2pmem_virt_to_bus(struct pci_dev *pdev, void *addr);
int pci_p2pmem_alloc_sgl(struct pci_dev *pdev, struct scatterlist **sgl,
		unsigned int *nents, u32 length);
void pci_p2pmem_free_sgl(struct pci_dev *pdev, struct scatterlist *sgl,
		unsigned int nents);
void pci_p2pmem_publish(struct pci_dev *pdev, bool publish);
#else /* CONFIG_PCI_P2PDMA */
static inline int pci_p2pdma_add_resource(struct pci_dev *pdev, int bar,
		size_t size, u64 offset)
{
	return 0;
}
static inline int pci_p2pdma_add_client(struct list_head *head,
		struct device *dev)
{
	return 0;
}
static inline void pci_p2pdma_remove_client(struct list_head *head,
		struct device *dev)
{
}
static inline void pci_p2pdma_client_list_free(struct list_head *head)
{
}
static inline struct pci_dev *pci_p2pmem_find(struct list_head *clients)
{
	return NULL;
}
static inline void *pci_alloc_p2pmem(struct pci_dev *pdev, size_t size)
{
	return NULL;
}
static inline void pci_free_p2pmem(struct pci_dev *pdev, void *addr,
		size_t size)
{
}
static inline pci_bus_addr_t pci_p2pmem_virt_to_bus(struct pci_dev *pdev,
						    void *addr)
{
	return 0;
}
static inline int pci_p2pmem_alloc_sgl(struct pci_dev *pdev,
		struct scatterlist **sgl, unsigned int *nents, u32 length)
{
	return -ENODEV;
}
static inline void pci_p2pmem_free_sgl(struct pci_dev *pdev,
		struct scatterlist *sgl, unsigned int nents)
{
}
static inline void pci_p2pmem_publish(struct pci_dev *pdev, bool publish)
{
}
#endif /* CONFIG_PCI_P2PDMA */
#endif /* _LINUX_PCI_P2P_H */
