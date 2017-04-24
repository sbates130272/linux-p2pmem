/*
 * Copyright(c) 2015 - 2017 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */
#include <linux/uio.h>
#include <linux/uaccess.h>
#include <linux/highmem.h>
#include <asm/cacheflush.h>
#include <asm/cpufeature.h>
#include <asm/special_insns.h>

/**
 * arch_wb_cache_pmem - write back a cache range with CLWB
 * @vaddr:	virtual start address
 * @size:	number of bytes to write back
 *
 * Write back a cache range using the CLWB (cache line write back)
 * instruction.
 */
void arch_wb_cache_pmem(void *addr, size_t size)
{
	u16 x86_clflush_size = boot_cpu_data.x86_clflush_size;
	unsigned long clflush_mask = x86_clflush_size - 1;
	void *vend = addr + size;
	void *p;

	for (p = (void *)((unsigned long)addr & ~clflush_mask);
	     p < vend; p += x86_clflush_size)
		clwb(p);
}
EXPORT_SYMBOL_GPL(arch_wb_cache_pmem);

void arch_invalidate_pmem(void *addr, size_t size)
{
	clflush_cache_range(addr, size);
}
EXPORT_SYMBOL_GPL(arch_invalidate_pmem);

void arch_memcpy_to_pmem(void *_dst, void *_src, unsigned size)
{
	unsigned long dest = (unsigned long) _dst;
	unsigned long source = (unsigned long) _src;

	/* cache copy and flush to align dest */
	if (!IS_ALIGNED(dest, 8)) {
		unsigned len = min_t(unsigned, size, ALIGN(dest, 8) - dest);

		memcpy((void *) dest, (void *) source, len);
		arch_wb_cache_pmem((void *) dest, len);
		dest += len;
		source += len;
		size -= len;
		if (!size)
			return;
	}

	/* 4x8 movnti loop */
	while (size >= 32) {
		asm("movq    (%0), %%r8\n"
		    "movq   8(%0), %%r9\n"
		    "movq  16(%0), %%r10\n"
		    "movq  24(%0), %%r11\n"
		    "movnti  %%r8,   (%1)\n"
		    "movnti  %%r9,  8(%1)\n"
		    "movnti %%r10, 16(%1)\n"
		    "movnti %%r11, 24(%1)\n"
		    :: "r" (source), "r" (dest)
		    : "memory", "r8", "r9", "r10", "r11");
		dest += 32;
		source += 32;
		size -= 32;
	}

	/* 1x8 movnti loop */
	while (size >= 8) {
		asm("movq    (%0), %%r8\n"
		    "movnti  %%r8,   (%1)\n"
		    :: "r" (source), "r" (dest)
		    : "memory", "r8");
		dest += 8;
		source += 8;
		size -= 8;
	}

	/* 1x4 movnti loop */
	while (size >= 4) {
		asm("movl    (%0), %%r8d\n"
		    "movnti  %%r8d,   (%1)\n"
		    :: "r" (source), "r" (dest)
		    : "memory", "r8");
		dest += 4;
		source += 4;
		size -= 4;
	}

	/* cache copy for remaining bytes */
	if (size) {
		memcpy((void *) dest, (void *) source, size);
		arch_wb_cache_pmem((void *) dest, size);
	}
}
EXPORT_SYMBOL_GPL(arch_memcpy_to_pmem);

static int pmem_from_user(void *dst, const void __user *src, unsigned size)
{
	unsigned long flushed, dest = (unsigned long) dest;
	int rc = __copy_from_user(dst, src, size);

	/*
	 * On x86_64 __copy_from_user_nocache() uses non-temporal stores
	 * for the bulk of the transfer, but we need to manually flush
	 * if the transfer is unaligned. A cached memory copy is used
	 * when destination or size is not naturally aligned. That is:
	 *   - Require 8-byte alignment when size is 8 bytes or larger.
	 *   - Require 4-byte alignment when size is 4 bytes.
	 */
	if (size < 8) {
		if (!IS_ALIGNED(dest, 4) || size != 4)
			arch_wb_cache_pmem(dst, 1);
	} else {
		if (!IS_ALIGNED(dest, 8)) {
			dest = ALIGN(dest, boot_cpu_data.x86_clflush_size);
			arch_wb_cache_pmem(dst, 1);
		}

		flushed = dest - (unsigned long) dst;
		if (size > flushed && !IS_ALIGNED(size - flushed, 8))
			arch_wb_cache_pmem(dst + size - 1, 1);
	}

	return rc;
}

static void pmem_from_page(char *to, struct page *page, size_t offset, size_t len)
{
	char *from = kmap_atomic(page);

	arch_memcpy_to_pmem(to, from + offset, len);
	kunmap_atomic(from);
}

size_t arch_copy_from_iter_pmem(void *addr, size_t bytes, struct iov_iter *i)
{
	return copy_from_iter_ops(addr, bytes, i, pmem_from_user, pmem_from_page,
			arch_memcpy_to_pmem);
}
EXPORT_SYMBOL_GPL(arch_copy_from_iter_pmem);
