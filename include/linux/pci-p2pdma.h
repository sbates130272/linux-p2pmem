/* SPDX-License-Identifier: GPL-2.0 */
/*
 * PCI Peer 2 Peer DMA support.
 *
 * Copyright (c) 2016-2018, Logan Gunthorpe
 * Copyright (c) 2016-2017, Microsemi Corporation
 * Copyright (c) 2017, Christoph Hellwig
 * Copyright (c) 2018, Eideticom Inc.
 *
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
int pci_p2pdma_distance(struct pci_dev *provider, struct list_head *clients,
			bool verbose);
bool pci_p2pdma_assign_provider(struct pci_dev *provider,
				struct list_head *clients);
bool pci_has_p2pmem(struct pci_dev *pdev);
struct pci_dev *pci_p2pmem_find(struct list_head *clients);
void *pci_alloc_p2pmem(struct pci_dev *pdev, size_t size);
void pci_free_p2pmem(struct pci_dev *pdev, void *addr, size_t size);
pci_bus_addr_t pci_p2pmem_virt_to_bus(struct pci_dev *pdev, void *addr);
struct scatterlist *pci_p2pmem_alloc_sgl(struct pci_dev *pdev,
					 unsigned int *nents, u32 length);
void pci_p2pmem_free_sgl(struct pci_dev *pdev, struct scatterlist *sgl);
void pci_p2pmem_publish(struct pci_dev *pdev, bool publish);
int pci_p2pdma_map_sg(struct device *dev, struct scatterlist *sg, int nents,
		      enum dma_data_direction dir);
void pci_p2pdma_unmap_sg(struct device *dev, struct scatterlist *sg, int nents,
			 enum dma_data_direction dir);
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
static inline int pci_p2pdma_distance(struct pci_dev *provider,
				      struct list_head *clients,
				      bool verbose)
{
	return -1;
}
static inline bool pci_p2pdma_assign_provider(struct pci_dev *provider,
					      struct list_head *clients)
{
	return false;
}
static inline bool pci_has_p2pmem(struct pci_dev *pdev)
{
	return false;
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
static inline struct scatterlist * pci_p2pmem_alloc_sgl(struct pci_dev *pdev,
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
static inline int pci_p2pdma_map_sg(struct device *dev,
	struct scatterlist *sg, int nents, enum dma_data_direction dir)
{
	return 0;
}
static inline void pci_p2pdma_unmap_sg(struct device *dev,
	struct scatterlist *sg, int nents, enum dma_data_direction dir)
{
}
#endif /* CONFIG_PCI_P2PDMA */
#endif /* _LINUX_PCI_P2P_H */
