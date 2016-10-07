/*
 * IOPMEM Block Device Driver
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
 * This driver is heavily based on drivers/block/pmem.c.
 * Copyright (c) 2014, Intel Corporation.
 * Copyright (C) 2007 Nick Piggin
 * Copyright (C) 2007 Novell Inc.
 */

#include <linux/blkdev.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/pfn_t.h>
#include <linux/memremap.h>

static const int BAR_ID = 4;

static struct pci_device_id iopmem_id_table[] = {
	{ PCI_DEVICE(0x11f8, 0xf115) },
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, iopmem_id_table);

struct iopmem_device {
	struct request_queue *queue;
	struct gendisk *disk;
	struct device *dev;

	int instance;

	/* One contiguous memory region per device */
	phys_addr_t		phys_addr;
	void			*virt_addr;
	size_t			size;
};

  /*
   * We can only access the iopmem device with full 32-bit word
   * accesses which cannot be gaurantee'd by the regular memcpy
   */

static void memcpy_from_iopmem(void *dst, const void *src, size_t sz)
{
	u64 *wdst = dst;
	const u64 *wsrc = src;
	u64 tmp;

	while (sz >= sizeof(*wdst)) {
		*wdst++ = *wsrc++;
		sz -= sizeof(*wdst);
	}

	if (!sz)
		return;

	tmp = *wsrc;
	memcpy(wdst, &tmp, sz);
}

static void write_iopmem(void *iopmem_addr, struct page *page,
		       unsigned int off, unsigned int len)
{
	void *mem = kmap_atomic(page);

	memcpy(iopmem_addr, mem + off, len);
	kunmap_atomic(mem);
}

static void read_iopmem(struct page *page, unsigned int off,
			void *iopmem_addr, unsigned int len)
{
	void *mem = kmap_atomic(page);

	memcpy_from_iopmem(mem + off, iopmem_addr, len);
	kunmap_atomic(mem);
}

static void iopmem_do_bvec(struct iopmem_device *iopmem, struct page *page,
			   unsigned int len, unsigned int off, bool is_write,
			   sector_t sector)
{
	phys_addr_t iopmem_off = sector * 512;
	void *iopmem_addr = iopmem->virt_addr + iopmem_off;

	if (!is_write) {
		read_iopmem(page, off, iopmem_addr, len);
		flush_dcache_page(page);
	} else {
		flush_dcache_page(page);
		write_iopmem(iopmem_addr, page, off, len);
	}
}

static blk_qc_t iopmem_make_request(struct request_queue *q, struct bio *bio)
{
	struct iopmem_device *iopmem = q->queuedata;
	struct bio_vec bvec;
	struct bvec_iter iter;

	bio_for_each_segment(bvec, bio, iter) {
		iopmem_do_bvec(iopmem, bvec.bv_page, bvec.bv_len,
			    bvec.bv_offset, op_is_write(bio_op(bio)),
			    iter.bi_sector);
	}

	bio_endio(bio);
	return BLK_QC_T_NONE;
}

static int iopmem_rw_page(struct block_device *bdev, sector_t sector,
		       struct page *page, bool is_write)
{
	struct iopmem_device *iopmem = bdev->bd_queue->queuedata;

	iopmem_do_bvec(iopmem, page, PAGE_SIZE, 0, is_write, sector);
	page_endio(page, is_write, 0);
	return 0;
}

static long iopmem_direct_access(struct block_device *bdev, sector_t sector,
			       void **kaddr, pfn_t *pfn, long size)
{
	struct iopmem_device *iopmem = bdev->bd_queue->queuedata;
	resource_size_t offset = sector * 512;

	if (!iopmem)
		return -ENODEV;

	*kaddr = iopmem->virt_addr + offset;
	 *pfn = phys_to_pfn_t(iopmem->phys_addr + offset, PFN_DEV | PFN_MAP);

	return iopmem->size - offset;
}

static const struct block_device_operations iopmem_fops = {
	.owner =		THIS_MODULE,
	.rw_page =		iopmem_rw_page,
	.direct_access =	iopmem_direct_access,
};

static DEFINE_IDA(iopmem_instance_ida);
static DEFINE_SPINLOCK(ida_lock);

static int iopmem_set_instance(struct iopmem_device *iopmem)
{
	int instance, error;

	do {
		if (!ida_pre_get(&iopmem_instance_ida, GFP_KERNEL))
			return -ENODEV;

		spin_lock(&ida_lock);
		error = ida_get_new(&iopmem_instance_ida, &instance);
		spin_unlock(&ida_lock);

	} while (error == -EAGAIN);

	if (error)
		return -ENODEV;

	iopmem->instance = instance;
	return 0;
}

static void iopmem_release_instance(struct iopmem_device *iopmem)
{
	spin_lock(&ida_lock);
	ida_remove(&iopmem_instance_ida, iopmem->instance);
	spin_unlock(&ida_lock);
}

static int iopmem_attach_disk(struct iopmem_device *iopmem)
{
	struct gendisk *disk;
	int nid = dev_to_node(iopmem->dev);
	struct request_queue *q = iopmem->queue;

	blk_queue_write_cache(q, true, true);
	blk_queue_make_request(q, iopmem_make_request);
	blk_queue_physical_block_size(q, PAGE_SIZE);
	blk_queue_max_hw_sectors(q, UINT_MAX);
	blk_queue_bounce_limit(q, BLK_BOUNCE_ANY);
	queue_flag_set_unlocked(QUEUE_FLAG_NONROT, q);
	queue_flag_set_unlocked(QUEUE_FLAG_DAX, q);
	q->queuedata = iopmem;

	disk = alloc_disk_node(0, nid);
	if (unlikely(!disk))
		return -ENOMEM;

	disk->fops		= &iopmem_fops;
	disk->queue		= q;
	disk->flags		= GENHD_FL_EXT_DEVT;
	sprintf(disk->disk_name, "iopmem%d", iopmem->instance);
	set_capacity(disk, iopmem->size / 512);
	iopmem->disk = disk;

	device_add_disk(iopmem->dev, disk);
	revalidate_disk(disk);

	return 0;
}

static void iopmem_detach_disk(struct iopmem_device *iopmem)
{
	del_gendisk(iopmem->disk);
	put_disk(iopmem->disk);
}

static int iopmem_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct iopmem_device *iopmem;
	struct device *dev;
	int err = 0;
	int nid = dev_to_node(&pdev->dev);

	if (pci_enable_device_mem(pdev) < 0) {
		dev_err(&pdev->dev, "unable to enable device!\n");
		goto out;
	}

	iopmem = kzalloc(sizeof(*iopmem), GFP_KERNEL);
	if (unlikely(!iopmem)) {
		err = -ENOMEM;
		goto out_disable_device;
	}

	iopmem->phys_addr = pci_resource_start(pdev, BAR_ID);
	iopmem->size = pci_resource_end(pdev, BAR_ID) - iopmem->phys_addr + 1;
	iopmem->dev = dev = get_device(&pdev->dev);
	pci_set_drvdata(pdev, iopmem);

	err = iopmem_set_instance(iopmem);
	if (err)
		goto out_put_device;

	dev_info(dev, "bar space 0x%llx len %lld\n",
		(unsigned long long) iopmem->phys_addr,
		(unsigned long long) iopmem->size);

	if (!devm_request_mem_region(dev, iopmem->phys_addr,
				     iopmem->size, dev_name(dev))) {
		dev_warn(dev, "could not reserve region [0x%pa:0x%zx]\n",
			 &iopmem->phys_addr, iopmem->size);
		err = -EBUSY;
		goto out_release_instance;
	}

	iopmem->queue = blk_alloc_queue_node(GFP_KERNEL, nid);
	if (!iopmem->queue) {
		err = -ENOMEM;
		goto out_release_instance;
	}

	iopmem->virt_addr = devm_memremap_pages(dev, &pdev->resource[BAR_ID],
				&iopmem->queue->q_usage_counter,
				NULL, MEMREMAP_WC);
	if (IS_ERR(iopmem->virt_addr)) {
		err = -ENXIO;
		goto out_free_queue;
	}

	err = iopmem_attach_disk(iopmem);
	if (err)
		goto out_free_queue;

	return 0;

out_free_queue:
	blk_cleanup_queue(iopmem->queue);
out_release_instance:
	iopmem_release_instance(iopmem);
out_put_device:
	put_device(&pdev->dev);
	kfree(iopmem);
out_disable_device:
	pci_disable_device(pdev);
out:
	return err;
}

static void iopmem_remove(struct pci_dev *pdev)
{
	struct iopmem_device *iopmem = pci_get_drvdata(pdev);

	blk_set_queue_dying(iopmem->queue);
	iopmem_detach_disk(iopmem);
	blk_cleanup_queue(iopmem->queue);
	iopmem_release_instance(iopmem);
	put_device(iopmem->dev);
	kfree(iopmem);
	pci_disable_device(pdev);
}

static struct pci_driver iopmem_pci_driver = {
	.name = "iopmem",
	.id_table = iopmem_id_table,
	.probe = iopmem_probe,
	.remove = iopmem_remove,
};

static int __init iopmem_init(void)
{
	int rc;

	rc = pci_register_driver(&iopmem_pci_driver);
	if (rc)
		return rc;

	pr_info("iopmem: module loaded\n");
	return 0;
}

static void __exit iopmem_exit(void)
{
	pci_unregister_driver(&iopmem_pci_driver);
	pr_info("iopmem: module unloaded\n");
}

MODULE_AUTHOR("Logan Gunthorpe <logang@deltatee.com>");
MODULE_LICENSE("GPL");
module_init(iopmem_init);
module_exit(iopmem_exit);
