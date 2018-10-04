/*
 * Copyright (C) 2012 Regents of the University of California
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation, version 2.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 */

#include <linux/init.h>
#include <linux/mm.h>
#include <linux/bootmem.h>
#include <linux/initrd.h>
#include <linux/memblock.h>
#include <linux/swap.h>
#include <linux/sizes.h>

#include <asm/tlbflush.h>
#include <asm/sections.h>
#include <asm/pgtable.h>
#include <asm/io.h>

static void __init zone_sizes_init(void)
{
	unsigned long max_zone_pfns[MAX_NR_ZONES] = { 0, };

#ifdef CONFIG_ZONE_DMA32
	max_zone_pfns[ZONE_DMA32] = PFN_DOWN(min(4UL * SZ_1G, max_low_pfn));
#endif
	max_zone_pfns[ZONE_NORMAL] = max_low_pfn;

	free_area_init_nodes(max_zone_pfns);
}

void setup_zero_page(void)
{
	memset((void *)empty_zero_page, 0, PAGE_SIZE);
}

void __init paging_init(void)
{
	setup_zero_page();
	local_flush_tlb_all();
	zone_sizes_init();
}

void __init mem_init(void)
{
#ifdef CONFIG_FLATMEM
	BUG_ON(!mem_map);
#endif /* CONFIG_FLATMEM */

	high_memory = (void *)(__va(PFN_PHYS(max_low_pfn)));
	free_all_bootmem();

	mem_init_print_info(NULL);
}

void free_initmem(void)
{
	free_initmem_default(0);
}

#ifdef CONFIG_BLK_DEV_INITRD
void free_initrd_mem(unsigned long start, unsigned long end)
{
}
#endif /* CONFIG_BLK_DEV_INITRD */

#ifdef CONFIG_SPARSEMEM
int __meminit vmemmap_populate(unsigned long start, unsigned long end, int node,
			       struct vmem_altmap *altmap)
{
	return vmemmap_populate_basepages(start, end, node);
}

#ifdef CONFIG_MEMORY_HOTREMOVE

void vmemmap_free(unsigned long start, unsigned long end,
		  struct vmem_altmap *altmap)
{
	/* TODO: free vmemmap pages on remove memory */
}
#endif
#endif

#ifdef CONFIG_MEMORY_HOTPLUG
int arch_add_memory(int nid, u64 start, u64 size, struct vmem_altmap *altmap,
		    bool want_memblock)
{
	unsigned long start_pfn = start >> PAGE_SHIFT;
	unsigned long nr_pages = size >> PAGE_SHIFT;
	int ret;

	if ((start + size) > -va_pa_offset) {
		pr_err("Cannot hotplug memory from %08llx to %08llx as it doesn't fall within the linear mapping\n",
		       start, start + size);
		return -EFAULT;
	}

	ret = __add_pages(nid, start_pfn, nr_pages, altmap, want_memblock);
	WARN_ON_ONCE(ret);

	return ret;
}

#ifdef CONFIG_MEMORY_HOTREMOVE
int __ref arch_remove_memory(u64 start, u64 size, struct vmem_altmap *altmap)
{
	unsigned long start_pfn = start >> PAGE_SHIFT;
	unsigned long nr_pages = size >> PAGE_SHIFT;
	struct page *page = pfn_to_page(start_pfn);
	struct zone *zone;
	int ret;

	if (altmap)
		page += vmem_altmap_offset(altmap);
	zone = page_zone(page);
	ret = __remove_pages(zone, start_pfn, nr_pages, altmap);
	WARN_ON_ONCE(ret);

	return ret;
}

#endif
#endif
