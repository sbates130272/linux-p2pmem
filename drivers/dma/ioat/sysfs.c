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

static ssize_t cap_show(struct device *dev, struct device_attribute *attr,
			char *page)
{
	struct dma_device *dma;

	CLASS(dma_chan_from_dev, c)(dev);

	if (!c)
		return -ENODEV;

	dma = c->device;
	return sysfs_emit(page, "copy%s%s%s%s%s\n",
		dma_has_cap(DMA_PQ, dma->cap_mask) ? " pq" : "",
		dma_has_cap(DMA_PQ_VAL, dma->cap_mask) ? " pq_val" : "",
		dma_has_cap(DMA_XOR, dma->cap_mask) ? " xor" : "",
		dma_has_cap(DMA_XOR_VAL, dma->cap_mask) ? " xor_val" : "",
		dma_has_cap(DMA_INTERRUPT, dma->cap_mask) ? " intr" : "");
}
static DEVICE_ATTR_RO(cap);

static ssize_t version_show(struct device *dev, struct device_attribute *attr,
			    char *page)
{
	struct ioatdma_device *ioat_dma;

	CLASS(dma_chan_from_dev, c)(dev);

	if (!c)
		return -ENODEV;

	ioat_dma = to_ioatdma_device(c->device);
	return sysfs_emit(page, "%d.%d\n",
			   ioat_dma->version >> 4, ioat_dma->version & 0xf);
}
static DEVICE_ATTR_RO(version);

static ssize_t ring_size_show(struct device *dev, struct device_attribute *attr,
			      char *page)
{
	CLASS(dma_chan_from_dev, c)(dev);

	if (!c)
		return -ENODEV;

	struct ioatdma_chan *ioat_chan = to_ioat_chan(c);

	return sysfs_emit(page, "%d\n", (1 << ioat_chan->alloc_order) & ~1);
}
static DEVICE_ATTR_RO(ring_size);

static ssize_t ring_active_show(struct device *dev,
				struct device_attribute *attr, char *page)
{
	CLASS(dma_chan_from_dev, c)(dev);

	if (!c)
		return -ENODEV;

	struct ioatdma_chan *ioat_chan = to_ioat_chan(c);

	/* ...taken outside the lock, no need to be precise */
	return sysfs_emit(page, "%d\n", ioat_ring_active(ioat_chan));
}
static DEVICE_ATTR_RO(ring_active);

static ssize_t intr_coalesce_show(struct device *dev,
				  struct device_attribute *attr, char *page)
{
	CLASS(dma_chan_from_dev, c)(dev);

	if (!c)
		return -ENODEV;

	struct ioatdma_chan *ioat_chan = to_ioat_chan(c);

	return sysfs_emit(page, "%d\n", ioat_chan->intr_coalesce);
}

static ssize_t intr_coalesce_store(struct device *dev,
				   struct device_attribute *attr,
				   const char *page, size_t count)
{
	int intr_coalesce = 0;

	CLASS(dma_chan_from_dev, c)(dev);

	if (!c)
		return -ENODEV;

	struct ioatdma_chan *ioat_chan = to_ioat_chan(c);

	if (sscanf(page, "%du", &intr_coalesce) != -1) {
		if ((intr_coalesce < 0) ||
		    (intr_coalesce > IOAT_INTRDELAY_MASK))
			return -EINVAL;
		ioat_chan->intr_coalesce = intr_coalesce;
	}

	return count;
}
static DEVICE_ATTR_RW(intr_coalesce);

static struct attribute *ioat_attrs[] = {
	&dev_attr_ring_size.attr,
	&dev_attr_ring_active.attr,
	&dev_attr_cap.attr,
	&dev_attr_version.attr,
	&dev_attr_intr_coalesce.attr,
	NULL,
};

static const struct attribute_group ioat_attr_group = {
	.name = "quickdata",
	.attrs = ioat_attrs,
};

const struct attribute_group *ioat_groups[] = {
	&ioat_attr_group,
	NULL,
};
