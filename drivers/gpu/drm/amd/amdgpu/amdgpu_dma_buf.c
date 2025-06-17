/*
 * Copyright 2019 Advanced Micro Devices, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * based on nouveau_prime.c
 *
 * Authors: Alex Deucher
 */

#define pr_fmt(fmt) "%s:%s: " fmt, KBUILD_MODNAME, __func__

/**
 * DOC: PRIME Buffer Sharing
 *
 * The following callback implementations are used for :ref:`sharing GEM buffer
 * objects between different devices via PRIME <prime_buffer_sharing>`.
 */

#include "amdgpu.h"
#include "amdgpu_display.h"
#include "amdgpu_gem.h"
#include "amdgpu_dma_buf.h"
#include "amdgpu_xgmi.h"
#include "amdgpu_vm.h"
#include <linux/pagemap.h>
#include <drm/amdgpu_drm.h>
#include <drm/ttm/ttm_tt.h>
#include <linux/dma-buf.h>
#include <linux/dma-fence-array.h>
#include <linux/pci-p2pdma.h>
#include <linux/blkdev.h>

static const struct dma_buf_attach_ops amdgpu_dma_buf_attach_ops;

/**
 * dma_buf_attach_adev - Helper to get adev of an attachment
 *
 * @attach: attachment
 *
 * Returns:
 * A struct amdgpu_device * if the attaching device is an amdgpu device or
 * partition, NULL otherwise.
 */
static struct amdgpu_device *dma_buf_attach_adev(struct dma_buf_attachment *attach)
{
	if (attach->importer_ops == &amdgpu_dma_buf_attach_ops) {
		struct drm_gem_object *obj = attach->importer_priv;
		struct amdgpu_bo *bo = gem_to_amdgpu_bo(obj);

		return amdgpu_ttm_adev(bo->tbo.bdev);
	}

	return NULL;
}

/**
 * amdgpu_dma_buf_attach - &dma_buf_ops.attach implementation
 *
 * @dmabuf: DMA-buf where we attach to
 * @attach: attachment to add
 *
 * Add the attachment as user to the exported DMA-buf.
 */
static int amdgpu_dma_buf_attach(struct dma_buf *dmabuf,
				 struct dma_buf_attachment *attach)
{
	struct amdgpu_device *attach_adev = dma_buf_attach_adev(attach);
	struct drm_gem_object *obj = dmabuf->priv;
	struct amdgpu_bo *bo = gem_to_amdgpu_bo(obj);
	struct amdgpu_device *adev = amdgpu_ttm_adev(bo->tbo.bdev);

	if (!amdgpu_dmabuf_is_xgmi_accessible(attach_adev, bo) &&
	    pci_p2pdma_distance(adev->pdev, attach->dev, false) < 0)
		attach->peer2peer = false;

	amdgpu_vm_bo_update_shared(bo);

	return 0;
}

/**
 * amdgpu_dma_buf_pin - &dma_buf_ops.pin implementation
 *
 * @attach: attachment to pin down
 *
 * Pin the BO which is backing the DMA-buf so that it can't move any more.
 */
static int amdgpu_dma_buf_pin(struct dma_buf_attachment *attach)
{
	struct dma_buf *dmabuf = attach->dmabuf;
	struct amdgpu_bo *bo = gem_to_amdgpu_bo(dmabuf->priv);
	u32 domains = bo->allowed_domains;

	dma_resv_assert_held(dmabuf->resv);

	/* Try pinning into VRAM to allow P2P with RDMA NICs without ODP
	 * support if all attachments can do P2P. If any attachment can't do
	 * P2P just pin into GTT instead.
	 *
	 * To avoid with conflicting pinnings between GPUs and RDMA when move
	 * notifiers are disabled, only allow pinning in VRAM when move
	 * notiers are enabled.
	 */
	if (!IS_ENABLED(CONFIG_DMABUF_MOVE_NOTIFY)) {
		domains &= ~AMDGPU_GEM_DOMAIN_VRAM;
	} else {
		list_for_each_entry(attach, &dmabuf->attachments, node)
			if (!attach->peer2peer)
				domains &= ~AMDGPU_GEM_DOMAIN_VRAM;
	}

	if (domains & AMDGPU_GEM_DOMAIN_VRAM)
		bo->flags |= AMDGPU_GEM_CREATE_CPU_ACCESS_REQUIRED;

	if (WARN_ON(!domains))
		return -EINVAL;

	return amdgpu_bo_pin(bo, domains);
}

/**
 * amdgpu_dma_buf_unpin - &dma_buf_ops.unpin implementation
 *
 * @attach: attachment to unpin
 *
 * Unpin a previously pinned BO to make it movable again.
 */
static void amdgpu_dma_buf_unpin(struct dma_buf_attachment *attach)
{
	struct drm_gem_object *obj = attach->dmabuf->priv;
	struct amdgpu_bo *bo = gem_to_amdgpu_bo(obj);

	amdgpu_bo_unpin(bo);
}

/**
 * amdgpu_dma_buf_map - &dma_buf_ops.map_dma_buf implementation
 * @attach: DMA-buf attachment
 * @dir: DMA direction
 *
 * Makes sure that the shared DMA buffer can be accessed by the target device.
 * For now, simply pins it to the GTT domain, where it should be accessible by
 * all DMA devices.
 *
 * Returns:
 * sg_table filled with the DMA addresses to use or ERR_PRT with negative error
 * code.
 */
static struct sg_table *amdgpu_dma_buf_map(struct dma_buf_attachment *attach,
					   enum dma_data_direction dir)
{
	struct dma_buf *dma_buf = attach->dmabuf;
	struct drm_gem_object *obj = dma_buf->priv;
	struct amdgpu_bo *bo = gem_to_amdgpu_bo(obj);
	struct amdgpu_device *adev = amdgpu_ttm_adev(bo->tbo.bdev);
	struct sg_table *sgt;
	long r;

	if (!bo->tbo.pin_count) {
		/* move buffer into GTT or VRAM */
		struct ttm_operation_ctx ctx = { false, false };
		unsigned int domains = AMDGPU_GEM_DOMAIN_GTT;

		if (bo->preferred_domains & AMDGPU_GEM_DOMAIN_VRAM &&
		    attach->peer2peer) {
			bo->flags |= AMDGPU_GEM_CREATE_CPU_ACCESS_REQUIRED;
			domains |= AMDGPU_GEM_DOMAIN_VRAM;
		}
		amdgpu_bo_placement_from_domain(bo, domains);
		r = ttm_bo_validate(&bo->tbo, &bo->placement, &ctx);
		if (r)
			return ERR_PTR(r);
	}

	switch (bo->tbo.resource->mem_type) {
	case TTM_PL_TT:
		sgt = drm_prime_pages_to_sg(obj->dev,
					    bo->tbo.ttm->pages,
					    bo->tbo.ttm->num_pages);
		if (IS_ERR(sgt))
			return sgt;

		if (dma_map_sgtable(attach->dev, sgt, dir,
				    DMA_ATTR_SKIP_CPU_SYNC))
			goto error_free;
		break;

	case TTM_PL_VRAM:
		/* XGMI-accessible memory should never be DMA-mapped */
		if (WARN_ON(amdgpu_dmabuf_is_xgmi_accessible(
				dma_buf_attach_adev(attach), bo)))
			return ERR_PTR(-EINVAL);

		r = amdgpu_vram_mgr_alloc_sgt(adev, bo->tbo.resource, 0,
					      bo->tbo.base.size, attach->dev,
					      dir, &sgt);
		if (r)
			return ERR_PTR(r);
		break;
	default:
		return ERR_PTR(-EINVAL);
	}

	return sgt;

error_free:
	sg_free_table(sgt);
	kfree(sgt);
	return ERR_PTR(-EBUSY);
}

/**
 * amdgpu_dma_buf_unmap - &dma_buf_ops.unmap_dma_buf implementation
 * @attach: DMA-buf attachment
 * @sgt: sg_table to unmap
 * @dir: DMA direction
 *
 * This is called when a shared DMA buffer no longer needs to be accessible by
 * another device. For now, simply unpins the buffer from GTT.
 */
static void amdgpu_dma_buf_unmap(struct dma_buf_attachment *attach,
				 struct sg_table *sgt,
				 enum dma_data_direction dir)
{
	if (sg_page(sgt->sgl)) {
		dma_unmap_sgtable(attach->dev, sgt, dir, 0);
		sg_free_table(sgt);
		kfree(sgt);
	} else {
		amdgpu_vram_mgr_free_sgt(attach->dev, dir, sgt);
	}
}

/**
 * amdgpu_dma_buf_begin_cpu_access - &dma_buf_ops.begin_cpu_access implementation
 * @dma_buf: Shared DMA buffer
 * @direction: Direction of DMA transfer
 *
 * This is called before CPU access to the shared DMA buffer's memory. If it's
 * a read access, the buffer is moved to the GTT domain if possible, for optimal
 * CPU read performance.
 *
 * Returns:
 * 0 on success or a negative error code on failure.
 */
static int amdgpu_dma_buf_begin_cpu_access(struct dma_buf *dma_buf,
					   enum dma_data_direction direction)
{
	struct amdgpu_bo *bo = gem_to_amdgpu_bo(dma_buf->priv);
	struct amdgpu_device *adev = amdgpu_ttm_adev(bo->tbo.bdev);
	struct ttm_operation_ctx ctx = { true, false };
	u32 domain = amdgpu_display_supported_domains(adev, bo->flags);
	int ret;
	bool reads = (direction == DMA_BIDIRECTIONAL ||
		      direction == DMA_FROM_DEVICE);

	if (!reads || !(domain & AMDGPU_GEM_DOMAIN_GTT))
		return 0;

	/* move to gtt */
	ret = amdgpu_bo_reserve(bo, false);
	if (unlikely(ret != 0))
		return ret;

	if (!bo->tbo.pin_count &&
	    (bo->allowed_domains & AMDGPU_GEM_DOMAIN_GTT)) {
		amdgpu_bo_placement_from_domain(bo, AMDGPU_GEM_DOMAIN_GTT);
		ret = ttm_bo_validate(&bo->tbo, &bo->placement, &ctx);
	}

	amdgpu_bo_unreserve(bo);
	return ret;
}

static struct pci_dev *get_pci_dev_from_file(struct file *file)
{
	struct device *dev = file->f_path.mnt->mnt_sb->s_bdev->bd_device.parent;
	struct pci_dev *pdev = NULL;

	/*
	 * TODO: Check if there is a better way to locate the
	 * DMA-capable parent of file based on either struct file or the
	 * file descriptor.
	*/

	while (dev && !dev_is_pci(dev)) {
		dev = dev->parent;
	}
	if (dev && dev_is_pci(dev)) {
		pdev = to_pci_dev(dev);
	}

	return pdev;
}

static struct bio_vec *amdgpu_init_bvec(struct sg_table *sgt,
					size_t offset,
					size_t len, int *nr_segs)
{
	struct scatterlist *sg;
	size_t length = 0;
	unsigned int i, k = 0;
	struct bio_vec *bvec;
	size_t sg_left;
	size_t sg_offset;
	size_t sg_len;
	struct page *page;

	bvec = kvcalloc(sgt->nents, sizeof(*bvec), GFP_KERNEL);
	if (!bvec)
		return NULL;

	for_each_sg(sgt->sgl, sg, sgt->nents, i) {
		length += sg->length;
		if (length <= offset)
			continue;

		sg_left = length - offset;
		sg_offset = sg->offset + sg->length - sg_left;
		sg_len = min(sg_left, len);

		page = pfn_to_page(PHYS_PFN(sg_dma_address(sg)));
		if (!page) {
			printk(KERN_ERR "Failed to get page for sg[%d]!\n", i);
			kvfree(bvec);
			return NULL;
		} else if (!is_pci_p2pdma_page(page)) {
			printk(KERN_ERR "page:%p is not PCI P2P page!\n", page);
			kvfree(bvec);
			return NULL;
		} else {
			printk(KERN_INFO "page:%p is PCI P2P page!\n", page);
		}
		bvec[k].bv_page = page;
		bvec[k].bv_len = sg_len;
		bvec[k].bv_offset = sg_offset;
		k++;

		offset += sg_len;
		len -= sg_len;
		if (len <= 0)
			break;
	}

	*nr_segs = k;
	return bvec;
}

static int amdgpu_rw_file(struct dma_buf *dmabuf, bool is_read,
                          bool direct_io, struct file *filp, loff_t file_offset,
                          size_t buf_offset, size_t len)
{
	struct sg_table *sgt;
	struct dma_buf_attachment attach;
	struct dma_buf_attach_ops ops;
	struct amdgpu_bo *bo;

	struct bio_vec *bvec;
	int nr_segs = 0;
	struct iov_iter iter;
	struct kiocb kiocb;
	int ret = 0;
	struct pci_dev *pdev;

	printk(KERN_INFO "is_read = %d!\n", is_read);
	printk(KERN_INFO "file_offset = %lld!\n", file_offset);
	printk(KERN_INFO "buf_offset = %zd!\n", buf_offset);
	printk(KERN_INFO "len = %zd!\n", len);

	if (direct_io) {
		if (!(filp->f_mode & FMODE_CAN_ODIRECT))
			return -EINVAL;
	}

	memset(&attach, 0, sizeof(attach));
	ops.allow_peer2peer = true;
	attach.dmabuf = dmabuf;
	attach.peer2peer = true;
	attach.importer_ops = &ops;

	pdev = get_pci_dev_from_file(filp);
	if (!pdev) {
		ret = -ENODEV;
		printk(KERN_ERR "Failed to get PCI device from file!\n");
		goto out;
	}
	attach.dev = &pdev->dev;

	sgt = dma_buf_map_attachment_unlocked(&attach, DMA_BIDIRECTIONAL);
	if (IS_ERR(sgt)) {
		ret = PTR_ERR(sgt);
		goto out;
	}

	bo = gem_to_amdgpu_bo(dmabuf->priv);
	if (!bo) {
		ret = -EINVAL;
		goto out;
	} else {
		/* Show BO domain to cross-check if it is in VRAM */
		dev_info(amdgpu_ttm_adev(bo->tbo.bdev)->dev, "DMA-BUF bo->tbo.base.size:%lx\n",
			 bo->tbo.base.size);
		dev_info(amdgpu_ttm_adev(bo->tbo.bdev)->dev, "mem_type:%x start:%lx size:%zx placement:%x\n",
			 bo->tbo.resource->mem_type, bo->tbo.resource->start,
			 bo->tbo.resource->size, bo->tbo.resource->placement);
	}

	if (pci_p2pdma_distance(pdev, amdgpu_ttm_adev(bo->tbo.bdev)->dev, false) < 0) {
		dev_info(amdgpu_ttm_adev(bo->tbo.bdev)->dev,
			 "DMA-BUF p2p not accessible!\n");
		ret = -ENODEV;
		goto out;
	}

	bvec = amdgpu_init_bvec(sgt, buf_offset, len, &nr_segs);
	if (!bvec) {
		ret = -ENOMEM;
		goto out;
	}

	iov_iter_bvec(&iter, is_read ? ITER_DEST : ITER_SOURCE, bvec, nr_segs, len);
	init_sync_kiocb(&kiocb, filp);
	kiocb.ki_pos = file_offset;
	if (direct_io)
		kiocb.ki_flags |= IOCB_DIRECT;

	while (kiocb.ki_pos < file_offset + len) {

		if (is_read)
			ret = vfs_iocb_iter_read(filp, &kiocb, &iter);
		else
			ret = vfs_iocb_iter_write(filp, &kiocb, &iter);
		if (ret <= 0)
			break;
	}

	kvfree(bvec);
	dma_buf_unmap_attachment_unlocked(&attach, sgt,
				 DMA_BIDIRECTIONAL);
out:
	return ret < 0 ? ret : 0;
}

/**
 * amdgpu_dma_buf_rw_file - &dma_buf_ops.rw_file implementation
 * @dma_buf: Shared DMA buffer
 * @dma_buf_rw_file: Struct with info on backing file
 *
 * This is a callback to enable both buffered and O_DIRECT IO between
 * an AMD GPU generated dma_buf and a file on any standard (VFS
 * supported) filesystem. Note that the backing-object associated with
 * the dma-buf is managed by this driver and thus this driver has full
 * control over the location and mappings.
 *
 * Returns:
 * 0 on success or a negative error code on failure.
 */
static int amdgpu_dma_buf_rw_file(struct dma_buf *dmabuf,
                                  struct dma_buf_rw_file *back)
{
	int ret = 0;
	__u32 op = back->flags & DMA_BUF_RW_FLAGS_OP_MASK;
	bool direct_io = back->flags & DMA_BUF_RW_FLAGS_DIRECT;
	struct file *filp;

	if (op != DMA_BUF_RW_FLAGS_READ && op != DMA_BUF_RW_FLAGS_WRITE)
		return -EINVAL;
	if (direct_io) {
		if (!PAGE_ALIGNED(back->file_offset) ||
		    !PAGE_ALIGNED(back->buf_offset) ||
		    !PAGE_ALIGNED(back->buf_len))
			return -EINVAL;
	}
	if (!back->buf_len || back->buf_len > dmabuf->size ||
		back->buf_offset >= dmabuf->size ||
		back->buf_offset + back->buf_len > dmabuf->size)
		return -EINVAL;
	if (back->file_offset + back->buf_len < back->file_offset)
		return -EINVAL;

	filp = fget(back->fd);
	if (!filp)
		return -EBADF;

	ret = amdgpu_rw_file(dmabuf, op == DMA_BUF_RW_FLAGS_READ,
			     direct_io, filp, back->file_offset,
			     back->buf_offset, back->buf_len);

	fput(filp);
	return ret;
}

const struct dma_buf_ops amdgpu_dmabuf_ops = {
	.attach = amdgpu_dma_buf_attach,
	.pin = amdgpu_dma_buf_pin,
	.unpin = amdgpu_dma_buf_unpin,
	.map_dma_buf = amdgpu_dma_buf_map,
	.unmap_dma_buf = amdgpu_dma_buf_unmap,
	.release = drm_gem_dmabuf_release,
	.begin_cpu_access = amdgpu_dma_buf_begin_cpu_access,
	.mmap = drm_gem_dmabuf_mmap,
	.vmap = drm_gem_dmabuf_vmap,
	.vunmap = drm_gem_dmabuf_vunmap,
        .rw_file = amdgpu_dma_buf_rw_file,
};

/**
 * amdgpu_gem_prime_export - &drm_driver.gem_prime_export implementation
 * @gobj: GEM BO
 * @flags: Flags such as DRM_CLOEXEC and DRM_RDWR.
 *
 * The main work is done by the &drm_gem_prime_export helper.
 *
 * Returns:
 * Shared DMA buffer representing the GEM BO from the given device.
 */
struct dma_buf *amdgpu_gem_prime_export(struct drm_gem_object *gobj,
					int flags)
{
	struct amdgpu_bo *bo = gem_to_amdgpu_bo(gobj);
	struct dma_buf *buf;

	if (amdgpu_ttm_tt_get_usermm(bo->tbo.ttm) ||
	    bo->flags & AMDGPU_GEM_CREATE_VM_ALWAYS_VALID)
		return ERR_PTR(-EPERM);

	buf = drm_gem_prime_export(gobj, flags);
	if (!IS_ERR(buf))
		buf->ops = &amdgpu_dmabuf_ops;

	return buf;
}

/**
 * amdgpu_dma_buf_create_obj - create BO for DMA-buf import
 *
 * @dev: DRM device
 * @dma_buf: DMA-buf
 *
 * Creates an empty SG BO for DMA-buf import.
 *
 * Returns:
 * A new GEM BO of the given DRM device, representing the memory
 * described by the given DMA-buf attachment and scatter/gather table.
 */
static struct drm_gem_object *
amdgpu_dma_buf_create_obj(struct drm_device *dev, struct dma_buf *dma_buf)
{
	struct dma_resv *resv = dma_buf->resv;
	struct amdgpu_device *adev = drm_to_adev(dev);
	struct drm_gem_object *gobj;
	struct amdgpu_bo *bo;
	uint64_t flags = 0;
	int ret;

	dma_resv_lock(resv, NULL);

	if (dma_buf->ops == &amdgpu_dmabuf_ops) {
		struct amdgpu_bo *other = gem_to_amdgpu_bo(dma_buf->priv);

		flags |= other->flags & (AMDGPU_GEM_CREATE_CPU_GTT_USWC |
					 AMDGPU_GEM_CREATE_COHERENT |
					 AMDGPU_GEM_CREATE_EXT_COHERENT |
					 AMDGPU_GEM_CREATE_UNCACHED);
	}

	ret = amdgpu_gem_object_create(adev, dma_buf->size, PAGE_SIZE,
				       AMDGPU_GEM_DOMAIN_CPU, flags,
				       ttm_bo_type_sg, resv, &gobj, 0);
	if (ret)
		goto error;

	bo = gem_to_amdgpu_bo(gobj);
	bo->allowed_domains = AMDGPU_GEM_DOMAIN_GTT;
	bo->preferred_domains = AMDGPU_GEM_DOMAIN_GTT;

	dma_resv_unlock(resv);
	return gobj;

error:
	dma_resv_unlock(resv);
	return ERR_PTR(ret);
}

/**
 * amdgpu_dma_buf_move_notify - &attach.move_notify implementation
 *
 * @attach: the DMA-buf attachment
 *
 * Invalidate the DMA-buf attachment, making sure that the we re-create the
 * mapping before the next use.
 */
static void
amdgpu_dma_buf_move_notify(struct dma_buf_attachment *attach)
{
	struct drm_gem_object *obj = attach->importer_priv;
	struct ww_acquire_ctx *ticket = dma_resv_locking_ctx(obj->resv);
	struct amdgpu_bo *bo = gem_to_amdgpu_bo(obj);
	struct amdgpu_device *adev = amdgpu_ttm_adev(bo->tbo.bdev);
	struct ttm_operation_ctx ctx = { false, false };
	struct ttm_placement placement = {};
	struct amdgpu_vm_bo_base *bo_base;
	int r;

	/* FIXME: This should be after the "if", but needs a fix to make sure
	 * DMABuf imports are initialized in the right VM list.
	 */
	amdgpu_vm_bo_invalidate(bo, false);
	if (!bo->tbo.resource || bo->tbo.resource->mem_type == TTM_PL_SYSTEM)
		return;

	r = ttm_bo_validate(&bo->tbo, &placement, &ctx);
	if (r) {
		DRM_ERROR("Failed to invalidate DMA-buf import (%d))\n", r);
		return;
	}

	for (bo_base = bo->vm_bo; bo_base; bo_base = bo_base->next) {
		struct amdgpu_vm *vm = bo_base->vm;
		struct dma_resv *resv = vm->root.bo->tbo.base.resv;

		if (ticket) {
			/* When we get an error here it means that somebody
			 * else is holding the VM lock and updating page tables
			 * So we can just continue here.
			 */
			r = dma_resv_lock(resv, ticket);
			if (r)
				continue;

		} else {
			/* TODO: This is more problematic and we actually need
			 * to allow page tables updates without holding the
			 * lock.
			 */
			if (!dma_resv_trylock(resv))
				continue;
		}

		/* Reserve fences for two SDMA page table updates */
		r = dma_resv_reserve_fences(resv, 2);
		if (!r)
			r = amdgpu_vm_clear_freed(adev, vm, NULL);
		if (!r)
			r = amdgpu_vm_handle_moved(adev, vm, ticket);

		if (r && r != -EBUSY)
			DRM_ERROR("Failed to invalidate VM page tables (%d))\n",
				  r);

		dma_resv_unlock(resv);
	}
}

static const struct dma_buf_attach_ops amdgpu_dma_buf_attach_ops = {
	.allow_peer2peer = true,
	.move_notify = amdgpu_dma_buf_move_notify
};

/**
 * amdgpu_gem_prime_import - &drm_driver.gem_prime_import implementation
 * @dev: DRM device
 * @dma_buf: Shared DMA buffer
 *
 * Import a dma_buf into a the driver and potentially create a new GEM object.
 *
 * Returns:
 * GEM BO representing the shared DMA buffer for the given device.
 */
struct drm_gem_object *amdgpu_gem_prime_import(struct drm_device *dev,
					       struct dma_buf *dma_buf)
{
	struct dma_buf_attachment *attach;
	struct drm_gem_object *obj;

	if (dma_buf->ops == &amdgpu_dmabuf_ops) {
		obj = dma_buf->priv;
		if (obj->dev == dev) {
			/*
			 * Importing dmabuf exported from out own gem increases
			 * refcount on gem itself instead of f_count of dmabuf.
			 */
			drm_gem_object_get(obj);
			return obj;
		}
	}

	obj = amdgpu_dma_buf_create_obj(dev, dma_buf);
	if (IS_ERR(obj))
		return obj;

	attach = dma_buf_dynamic_attach(dma_buf, dev->dev,
					&amdgpu_dma_buf_attach_ops, obj);
	if (IS_ERR(attach)) {
		drm_gem_object_put(obj);
		return ERR_CAST(attach);
	}

	get_dma_buf(dma_buf);
	obj->import_attach = attach;
	return obj;
}

/**
 * amdgpu_dmabuf_is_xgmi_accessible - Check if xgmi available for P2P transfer
 *
 * @adev: amdgpu_device pointer of the importer
 * @bo: amdgpu buffer object
 *
 * Returns:
 * True if dmabuf accessible over xgmi, false otherwise.
 */
bool amdgpu_dmabuf_is_xgmi_accessible(struct amdgpu_device *adev,
				      struct amdgpu_bo *bo)
{
	struct drm_gem_object *obj = &bo->tbo.base;
	struct drm_gem_object *gobj;

	if (!adev)
		return false;

	if (obj->import_attach) {
		struct dma_buf *dma_buf = obj->import_attach->dmabuf;

		if (dma_buf->ops != &amdgpu_dmabuf_ops)
			/* No XGMI with non AMD GPUs */
			return false;

		gobj = dma_buf->priv;
		bo = gem_to_amdgpu_bo(gobj);
	}

	if (amdgpu_xgmi_same_hive(adev, amdgpu_ttm_adev(bo->tbo.bdev)) &&
			(bo->preferred_domains & AMDGPU_GEM_DOMAIN_VRAM))
		return true;

	return false;
}
