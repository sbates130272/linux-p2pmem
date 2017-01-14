#ifndef __NVDIMM_PMEM_H__
#define __NVDIMM_PMEM_H__
#include <linux/badblocks.h>
#include <linux/types.h>
#include <linux/pfn_t.h>
#include <linux/uio.h>
#include <linux/fs.h>

#ifdef CONFIG_ARCH_HAS_PMEM_API
void arch_wb_cache_pmem(void *addr, size_t size);
void arch_invalidate_pmem(void *addr, size_t size);
size_t arch_copy_from_iter_pmem(void *addr, size_t bytes, struct iov_iter *i);
#else
static inline void arch_wb_cache_pmem(void *addr, size_t size)
{
}
static inline void arch_invalidate_pmem(void *addr, size_t size)
{
}
static inline size_t arch_copy_from_iter_pmem(void *addr, size_t bytes,
		struct iov_iter *i)
{
	return copy_from_iter_nocache(addr, bytes, i);
}
#endif

/* this definition is in it's own header for tools/testing/nvdimm to consume */
struct pmem_device {
	/* One contiguous memory region per device */
	phys_addr_t		phys_addr;
	/* when non-zero this device is hosting a 'pfn' instance */
	phys_addr_t		data_offset;
	u64			pfn_flags;
	void			*virt_addr;
	/* immutable base size of the namespace */
	size_t			size;
	/* trim size when namespace capacity has been section aligned */
	u32			pfn_pad;
	struct badblocks	bb;
	struct dax_device	*dax_dev;
	struct gendisk		*disk;
};

long __pmem_direct_access(struct pmem_device *pmem, pgoff_t pgoff,
		long nr_pages, void **kaddr, pfn_t *pfn);
#endif /* __NVDIMM_PMEM_H__ */
