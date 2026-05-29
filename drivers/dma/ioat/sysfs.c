// SPDX-License-Identifier: GPL-2.0-only
/*
 * Intel I/OAT DMA Linux driver
 * Copyright(c) 2004 - 2015 Intel Corporation.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/dmaengine.h>
#include <linux/pci.h>
#include "dma.h"
#include "registers.h"
#include "hw.h"

#include "../dmaengine.h"

static ssize_t cap_show(struct dma_chan *c, char *page)
{
	struct dma_device *dma = c->device;

	return sprintf(page, "copy%s%s%s%s%s\n",
		       dma_has_cap(DMA_PQ, dma->cap_mask) ? " pq" : "",
		       dma_has_cap(DMA_PQ_VAL, dma->cap_mask) ? " pq_val" : "",
		       dma_has_cap(DMA_XOR, dma->cap_mask) ? " xor" : "",
		       dma_has_cap(DMA_XOR_VAL, dma->cap_mask) ? " xor_val" : "",
		       dma_has_cap(DMA_INTERRUPT, dma->cap_mask) ? " intr" : "");

}
static const struct dma_chan_sysfs_entry ioat_cap_attr = __ATTR_RO(cap);

static ssize_t version_show(struct dma_chan *c, char *page)
{
	struct dma_device *dma = c->device;
	struct ioatdma_device *ioat_dma = to_ioatdma_device(dma);

	return sprintf(page, "%d.%d\n",
		       ioat_dma->version >> 4, ioat_dma->version & 0xf);
}
static const struct dma_chan_sysfs_entry ioat_version_attr = __ATTR_RO(version);

static ssize_t ring_size_show(struct dma_chan *c, char *page)
{
	struct ioatdma_chan *ioat_chan = to_ioat_chan(c);

	return sprintf(page, "%d\n", (1 << ioat_chan->alloc_order) & ~1);
}
static const struct dma_chan_sysfs_entry ring_size_attr = __ATTR_RO(ring_size);

static ssize_t ring_active_show(struct dma_chan *c, char *page)
{
	struct ioatdma_chan *ioat_chan = to_ioat_chan(c);

	/* ...taken outside the lock, no need to be precise */
	return sprintf(page, "%d\n", ioat_ring_active(ioat_chan));
}
static const struct dma_chan_sysfs_entry ring_active_attr = __ATTR_RO(ring_active);

static ssize_t intr_coalesce_show(struct dma_chan *c, char *page)
{
	struct ioatdma_chan *ioat_chan = to_ioat_chan(c);

	return sprintf(page, "%d\n", ioat_chan->intr_coalesce);
}

static ssize_t intr_coalesce_store(struct dma_chan *c, const char *page,
size_t count)
{
	int intr_coalesce = 0;
	struct ioatdma_chan *ioat_chan = to_ioat_chan(c);

	if (sscanf(page, "%du", &intr_coalesce) != -1) {
		if ((intr_coalesce < 0) ||
		    (intr_coalesce > IOAT_INTRDELAY_MASK))
			return -EINVAL;
		ioat_chan->intr_coalesce = intr_coalesce;
	}

	return count;
}

static const struct dma_chan_sysfs_entry intr_coalesce_attr = __ATTR_RW(intr_coalesce);

static const struct attribute *const ioat_attrs[] = {
	&ring_size_attr.attr,
	&ring_active_attr.attr,
	&ioat_cap_attr.attr,
	&ioat_version_attr.attr,
	&intr_coalesce_attr.attr,
	NULL,
};
ATTRIBUTE_GROUPS(ioat);

const struct kobj_type ioat_ktype = {
	.sysfs_ops = &dma_chan_sysfs_ops,
	.default_groups = ioat_groups,
};
