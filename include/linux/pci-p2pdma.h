/* SPDX-License-Identifier: GPL-2.0 */
/*
 * PCI Peer 2 Peer DMA support.
 *
 * Copyright (c) 2016-2018, Logan Gunthorpe
 * Copyright (c) 2016-2017, Microsemi Corporation
 * Copyright (c) 2017, Christoph Hellwig
 * Copyright (c) 2018, Eideticom Inc.
 */

#ifndef _LINUX_PCI_P2PDMA_H
#define _LINUX_PCI_P2PDMA_H

#include <linux/pci.h>

struct pci_p2pdma_map_state {
	struct dev_pagemap *pgmap;
	int map;
	u64 bus_off;
};

struct block_device;
struct scatterlist;

enum pci_p2pdma_map_type {
	/*
	 * PCI_P2PDMA_MAP_UNKNOWN: Used internally for indicating the mapping
	 * type hasn't been calculated yet. Functions that return this enum
	 * never return this value.
	 */
	PCI_P2PDMA_MAP_UNKNOWN = 0,

	/*
	 * PCI_P2PDMA_MAP_NOT_SUPPORTED: Indicates the transaction will
	 * traverse the host bridge and the host bridge is not in the
	 * whitelist. DMA Mapping routines should return an error when
	 * this is returned.
	 */
	PCI_P2PDMA_MAP_NOT_SUPPORTED,

	/*
	 * PCI_P2PDMA_BUS_ADDR: Indicates that two devices can talk to
	 * eachother directly through a PCI switch and the transaction will
	 * not traverse the host bridge. Such a mapping should program
	 * the DMA engine with PCI bus addresses.
	 */
	PCI_P2PDMA_MAP_BUS_ADDR,

	/*
	 * PCI_P2PDMA_MAP_THRU_HOST_BRIDGE: Indicates two devices can talk
	 * to eachother, but the transaction traverses a host bridge on the
	 * whitelist. In this case, a normal mapping either with CPU physical
	 * addresses (in the case of dma-direct) or IOVA addresses (in the
	 * case of IOMMUs) should be used to program the DMA engine.
	 */
	PCI_P2PDMA_MAP_THRU_HOST_BRIDGE,
};

#ifdef CONFIG_PCI_P2PDMA
int pci_p2pdma_add_resource(struct pci_dev *pdev, int bar, size_t size,
		u64 offset);
int pci_p2pdma_distance_many(struct pci_dev *provider, struct device **clients,
			     int num_clients, bool verbose);
bool pci_has_p2pmem(struct pci_dev *pdev);
struct pci_dev *pci_p2pmem_find_many(struct device **clients, int num_clients);
void *pci_alloc_p2pmem(struct pci_dev *pdev, size_t size);
void pci_free_p2pmem(struct pci_dev *pdev, void *addr, size_t size);
pci_bus_addr_t pci_p2pmem_virt_to_bus(struct pci_dev *pdev, void *addr);
struct scatterlist *pci_p2pmem_alloc_sgl(struct pci_dev *pdev,
					 unsigned int *nents, u32 length);
void pci_p2pmem_free_sgl(struct pci_dev *pdev, struct scatterlist *sgl);
void pci_p2pmem_publish(struct pci_dev *pdev, bool publish);
enum pci_p2pdma_map_type pci_p2pdma_map_type(struct dev_pagemap *pgmap,
					     struct device *dev);
enum pci_p2pdma_map_type
pci_p2pdma_map_segment(struct pci_p2pdma_map_state *state, struct device *dev,
		       struct scatterlist *sg);
void pci_p2pdma_map_bus_segment(struct scatterlist *pg_sg,
				struct scatterlist *dma_sg);
int pci_p2pdma_enable_store(const char *page, struct pci_dev **p2p_dev,
			    bool *use_p2pdma);
ssize_t pci_p2pdma_enable_show(char *page, struct pci_dev *p2p_dev,
			       bool use_p2pdma);
void pci_p2pdma_mmap_file_open(struct pci_dev *pdev, struct file *file);
int pci_mmap_p2pmem(struct pci_dev *pdev, struct vm_area_struct *vma);
#else /* CONFIG_PCI_P2PDMA */
static inline int pci_p2pdma_add_resource(struct pci_dev *pdev, int bar,
		size_t size, u64 offset)
{
	return -EOPNOTSUPP;
}
static inline int pci_p2pdma_distance_many(struct pci_dev *provider,
	struct device **clients, int num_clients, bool verbose)
{
	return -1;
}
static inline bool pci_has_p2pmem(struct pci_dev *pdev)
{
	return false;
}
static inline struct pci_dev *pci_p2pmem_find_many(struct device **clients,
						   int num_clients)
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
static inline struct scatterlist *pci_p2pmem_alloc_sgl(struct pci_dev *pdev,
		unsigned int *nents, u32 length)
{
	return NULL;
}
static inline void pci_p2pmem_free_sgl(struct pci_dev *pdev,
		struct scatterlist *sgl)
{
}
static inline void pci_p2pmem_publish(struct pci_dev *pdev, bool publish)
{
}
static inline enum pci_p2pdma_map_type
pci_p2pdma_map_type(struct dev_pagemap *pgmap, struct device *dev)
{
	return PCI_P2PDMA_MAP_NOT_SUPPORTED;
}
static inline enum pci_p2pdma_map_type
pci_p2pdma_map_segment(struct pci_p2pdma_map_state *state, struct device *dev,
		       struct scatterlist *sg)
{
	return PCI_P2PDMA_MAP_NOT_SUPPORTED;
}
static inline void pci_p2pdma_map_bus_segment(struct scatterlist *pg_sg,
					      struct scatterlist *dma_sg)
{
}
static inline int pci_p2pdma_enable_store(const char *page,
		struct pci_dev **p2p_dev, bool *use_p2pdma)
{
	*use_p2pdma = false;
	return 0;
}
static inline ssize_t pci_p2pdma_enable_show(char *page,
		struct pci_dev *p2p_dev, bool use_p2pdma)
{
	return sprintf(page, "none\n");
}
static inline void pci_p2pdma_mmap_file_open(struct pci_dev *pdev,
					     struct file *file)
{
}
static inline int pci_mmap_p2pmem(struct pci_dev *pdev,
				  struct vm_area_struct *vma)
{
	return -EOPNOTSUPP;
}
#endif /* CONFIG_PCI_P2PDMA */


static inline int pci_p2pdma_distance(struct pci_dev *provider,
	struct device *client, bool verbose)
{
	return pci_p2pdma_distance_many(provider, &client, 1, verbose);
}

static inline struct pci_dev *pci_p2pmem_find(struct device *client)
{
	return pci_p2pmem_find_many(&client, 1);
}

#endif /* _LINUX_PCI_P2P_H */
