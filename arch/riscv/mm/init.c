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
#include <linux/memblock.h>
#include <linux/initrd.h>
#include <linux/swap.h>
#include <linux/sizes.h>
#include <linux/of_fdt.h>

#include <asm/fixmap.h>
#include <asm/tlbflush.h>
#include <asm/sections.h>
#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/io.h>

unsigned long empty_zero_page[PAGE_SIZE / sizeof(unsigned long)]
							__page_aligned_bss;
EXPORT_SYMBOL(empty_zero_page);

static void __init zone_sizes_init(void)
{
	unsigned long max_zone_pfns[MAX_NR_ZONES] = { 0, };

#ifdef CONFIG_ZONE_DMA32
	max_zone_pfns[ZONE_DMA32] = PFN_DOWN(min(4UL * SZ_1G,
			(unsigned long) PFN_PHYS(max_low_pfn)));
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
	memblock_free_all();

	mem_init_print_info(NULL);
}

void free_initmem(void)
{
	free_initmem_default(0);
}

#ifdef CONFIG_BLK_DEV_INITRD
static void __init setup_initrd(void)
{
	unsigned long size;

	if (initrd_start >= initrd_end) {
		pr_info("initrd not found or empty");
		goto disable;
	}
	if (__pa(initrd_end) > PFN_PHYS(max_low_pfn)) {
		pr_err("initrd extends beyond end of memory");
		goto disable;
	}

	size = initrd_end - initrd_start;
	memblock_reserve(__pa(initrd_start), size);
	initrd_below_start_ok = 1;

	pr_info("Initial ramdisk at: 0x%p (%lu bytes)\n",
		(void *)(initrd_start), size);
	return;
disable:
	pr_cont(" - disabling initrd\n");
	initrd_start = 0;
	initrd_end = 0;
}

void __init free_initrd_mem(unsigned long start, unsigned long end)
{
	free_reserved_area((void *)start, (void *)end, -1, "initrd");
}
#endif /* CONFIG_BLK_DEV_INITRD */

void __init setup_bootmem(void)
{
	struct memblock_region *reg;
	phys_addr_t mem_size = 0;

	/* Find the memory region containing the kernel */
	for_each_memblock(memory, reg) {
		phys_addr_t vmlinux_end = __pa(_end);
		phys_addr_t end = reg->base + reg->size;

		if (reg->base <= vmlinux_end && vmlinux_end <= end) {
			/*
			 * Reserve from the start of the region to the end of
			 * the kernel
			 */
			memblock_reserve(reg->base, vmlinux_end - reg->base);
			mem_size = min(reg->size, (phys_addr_t)-PAGE_OFFSET);

			/*
			 * Remove memblock from the end of usable area to the
			 * end of region
			 */
			if (reg->base + mem_size < end)
				memblock_remove(reg->base + mem_size,
						end - reg->base - mem_size);
		}
	}
	BUG_ON(mem_size == 0);

	set_max_mapnr(PFN_DOWN(mem_size));
	max_low_pfn = PFN_DOWN(memblock_end_of_DRAM());

#ifdef CONFIG_BLK_DEV_INITRD
	setup_initrd();
#endif /* CONFIG_BLK_DEV_INITRD */

	early_init_fdt_reserve_self();
	early_init_fdt_scan_reserved_mem();
	memblock_allow_resize();
	memblock_dump_all();

	for_each_memblock(memory, reg) {
		unsigned long start_pfn = memblock_region_memory_base_pfn(reg);
		unsigned long end_pfn = memblock_region_memory_end_pfn(reg);

		memblock_set_node(PFN_PHYS(start_pfn),
				  PFN_PHYS(end_pfn - start_pfn),
				  &memblock.memory, 0);
	}

	memblocks_present();
	sparse_init();
}

unsigned long va_pa_offset;
EXPORT_SYMBOL(va_pa_offset);
unsigned long pfn_base;
EXPORT_SYMBOL(pfn_base);

pgd_t swapper_pg_dir[PTRS_PER_PGD] __page_aligned_bss;
pgd_t trampoline_pg_dir[PTRS_PER_PGD] __initdata __aligned(PAGE_SIZE);

#ifndef __PAGETABLE_PMD_FOLDED
#define NUM_SWAPPER_PMDS ((uintptr_t)-PAGE_OFFSET >> PGDIR_SHIFT)
pmd_t swapper_pmd[PTRS_PER_PMD*((-PAGE_OFFSET)/PGDIR_SIZE)] __page_aligned_bss;
pmd_t trampoline_pmd[PTRS_PER_PGD] __initdata __aligned(PAGE_SIZE);
pmd_t fixmap_pmd[PTRS_PER_PMD] __page_aligned_bss;
#endif

pte_t fixmap_pte[PTRS_PER_PTE] __page_aligned_bss;

void __set_fixmap(enum fixed_addresses idx, phys_addr_t phys, pgprot_t prot)
{
	unsigned long addr = __fix_to_virt(idx);
	pte_t *ptep;

	BUG_ON(idx <= FIX_HOLE || idx >= __end_of_fixed_addresses);

	ptep = &fixmap_pte[pte_index(addr)];

	if (pgprot_val(prot)) {
		set_pte(ptep, pfn_pte(phys >> PAGE_SHIFT, prot));
	} else {
		pte_clear(&init_mm, addr, ptep);
		local_flush_tlb_page(addr);
	}
}

/*
 * setup_vm() is called from head.S with MMU-off.
 *
 * Following requirements should be honoured for setup_vm() to work
 * correctly:
 * 1) It should use PC-relative addressing for accessing kernel symbols.
 *    To achieve this we always use GCC cmodel=medany.
 * 2) The compiler instrumentation for FTRACE will not work for setup_vm()
 *    so disable compiler instrumentation when FTRACE is enabled.
 *
 * Currently, the above requirements are honoured by using custom CFLAGS
 * for init.o in mm/Makefile.
 */

#ifndef __riscv_cmodel_medany
#error "setup_vm() is called from head.S before relocate so it should "
	"not use absolute addressing."
#endif

asmlinkage void __init setup_vm(void)
{
	extern char _start;
	uintptr_t i;
	uintptr_t pa = (uintptr_t) &_start;
	pgprot_t prot = __pgprot(pgprot_val(PAGE_KERNEL) | _PAGE_EXEC);

	va_pa_offset = PAGE_OFFSET - pa;
	pfn_base = PFN_DOWN(pa);

	/* Sanity check alignment and size */
	BUG_ON((PAGE_OFFSET % PGDIR_SIZE) != 0);
	BUG_ON((pa % (PAGE_SIZE * PTRS_PER_PTE)) != 0);

#ifndef __PAGETABLE_PMD_FOLDED
	trampoline_pg_dir[(PAGE_OFFSET >> PGDIR_SHIFT) % PTRS_PER_PGD] =
		pfn_pgd(PFN_DOWN((uintptr_t)trampoline_pmd),
			__pgprot(_PAGE_TABLE));
	trampoline_pmd[0] = pfn_pmd(PFN_DOWN(pa), prot);

	for (i = 0; i < (-PAGE_OFFSET)/PGDIR_SIZE; ++i) {
		size_t o = (PAGE_OFFSET >> PGDIR_SHIFT) % PTRS_PER_PGD + i;

		swapper_pg_dir[o] =
			pfn_pgd(PFN_DOWN((uintptr_t)swapper_pmd) + i,
				__pgprot(_PAGE_TABLE));
	}
	for (i = 0; i < ARRAY_SIZE(swapper_pmd); i++)
		swapper_pmd[i] = pfn_pmd(PFN_DOWN(pa + i * PMD_SIZE), prot);

	swapper_pg_dir[(FIXADDR_START >> PGDIR_SHIFT) % PTRS_PER_PGD] =
		pfn_pgd(PFN_DOWN((uintptr_t)fixmap_pmd),
				__pgprot(_PAGE_TABLE));
	fixmap_pmd[(FIXADDR_START >> PMD_SHIFT) % PTRS_PER_PMD] =
		pfn_pmd(PFN_DOWN((uintptr_t)fixmap_pte),
				__pgprot(_PAGE_TABLE));
#else
	trampoline_pg_dir[(PAGE_OFFSET >> PGDIR_SHIFT) % PTRS_PER_PGD] =
		pfn_pgd(PFN_DOWN(pa), prot);

	for (i = 0; i < (-PAGE_OFFSET)/PGDIR_SIZE; ++i) {
		size_t o = (PAGE_OFFSET >> PGDIR_SHIFT) % PTRS_PER_PGD + i;

		swapper_pg_dir[o] =
			pfn_pgd(PFN_DOWN(pa + i * PGDIR_SIZE), prot);
	}

	swapper_pg_dir[(FIXADDR_START >> PGDIR_SHIFT) % PTRS_PER_PGD] =
		pfn_pgd(PFN_DOWN((uintptr_t)fixmap_pte),
				__pgprot(_PAGE_TABLE));
#endif
}

#ifdef CONFIG_SPARSEMEM
int __meminit vmemmap_populate(unsigned long start, unsigned long end, int node,
			       struct vmem_altmap *altmap)
{
	return vmemmap_populate_basepages(start, end, node);
}
#endif

#ifdef CONFIG_MEMORY_HOTPLUG
static void __meminit free_pagetable(struct page *page, int order)
{
	unsigned long magic;
	unsigned int nr_pages = 1 << order;

	/* bootmem page has reserved flag */
	if (PageReserved(page)) {
		__ClearPageReserved(page);

		magic = (unsigned long)page->freelist;
		if (magic == SECTION_INFO || magic == MIX_SECTION_INFO) {
			while (nr_pages--)
				put_page_bootmem(page++);
		} else {
			while (nr_pages--)
				free_reserved_page(page++);
		}
	} else {
		free_pages((unsigned long)page_address(page), order);
	}
}

static void __meminit free_pte_table(pte_t *pte_start, pmd_t *pmd)
{
	pte_t *pte;
	int i;

	for (i = 0; i < PTRS_PER_PTE; i++) {
		pte = pte_start + i;
		if (!pte_none(*pte))
			return;
	}

	/* free a pte table */
	free_pagetable(pmd_page(*pmd), 0);
	spin_lock(&init_mm.page_table_lock);
	pmd_clear(pmd);
	spin_unlock(&init_mm.page_table_lock);
}

static void __meminit free_pmd_table(pmd_t *pmd_start, pud_t *pud)
{
	pmd_t *pmd;
	int i;

	for (i = 0; i < PTRS_PER_PMD; i++) {
		pmd = pmd_start + i;
		if (!pmd_none(*pmd))
			return;
	}

	/* free a pmd table */
	free_pagetable(pud_page(*pud), 0);
	spin_lock(&init_mm.page_table_lock);
	pud_clear(pud);
	spin_unlock(&init_mm.page_table_lock);
}

static void __meminit remove_pte_table(pte_t *pte_start, unsigned long addr,
				       unsigned long end)
{
	unsigned long next;
	pte_t *pte;

	pte = pte_start + pte_index(addr);
	for (; addr < end; addr = next, pte++) {
		next = (addr + PAGE_SIZE) & PAGE_MASK;
		if (next > end)
			next = end;

		if (!pte_present(*pte))
			continue;

		free_pagetable(pte_page(*pte), 0);

		spin_lock(&init_mm.page_table_lock);
		pte_clear(&init_mm, addr, pte);
		spin_unlock(&init_mm.page_table_lock);
	}

	flush_tlb_all();
}

static void __meminit remove_pmd_table(pmd_t *pmd_start, unsigned long addr,
				       unsigned long end)
{
	unsigned long next;
	pte_t *pte_base;
	pmd_t *pmd;

	pmd = pmd_start + pmd_index(addr);
	for (; addr < end; addr = next, pmd++) {
		next = pmd_addr_end(addr, end);

		if (!pmd_present(*pmd))
			continue;

		pte_base = (pte_t *)pmd_page_vaddr(*pmd);
		remove_pte_table(pte_base, addr, next);
		free_pte_table(pte_base, pmd);
	}
}

static void __meminit
remove_pud_table(pud_t *pud_start, unsigned long addr, unsigned long end)
{
	unsigned long next;
	pmd_t *pmd_base;
	pud_t *pud;

	pud = pud_start + pud_index(addr);
	for (; addr < end; addr = next, pud++) {
		next = pud_addr_end(addr, end);

		if (!pud_present(*pud))
			continue;

		pmd_base = pmd_offset(pud, 0);
		remove_pmd_table(pmd_base, addr, next);
		free_pmd_table(pmd_base, pud);
	}
}

static void __meminit remove_p4d_table(p4d_t *p4d_start, unsigned long addr,
				       unsigned long end)
{
	unsigned long next;
	pud_t *pud_base;
	p4d_t *p4d;

	p4d = p4d_start + p4d_index(addr);
	for (; addr < end; addr = next, p4d++) {
		next = p4d_addr_end(addr, end);

		if (!p4d_present(*p4d))
			continue;

		pud_base = pud_offset(p4d, 0);
		remove_pud_table(pud_base, addr, next);
	}
}

/* start and end are both virtual address. */
static void __meminit remove_pagetable(unsigned long start, unsigned long end)
{
	unsigned long next;
	unsigned long addr;
	pgd_t *pgd;
	p4d_t *p4d;

	for (addr = start; addr < end; addr = next) {
		next = pgd_addr_end(addr, end);

		pgd = pgd_offset_k(addr);
		if (!pgd_present(*pgd))
			continue;

		p4d = p4d_offset(pgd, 0);
		remove_p4d_table(p4d, addr, next);
	}

	flush_tlb_all();
}

void vmemmap_free(unsigned long start, unsigned long end,
		  struct vmem_altmap *altmap)
{
	remove_pagetable(start, end);
}

static void add_pte_pagetable(pmd_t *pmd, unsigned long virt, unsigned long end,
			      phys_addr_t phys, pgprot_t prot)
{
	pte_t entry, *pte;

	for (; virt < end; virt += PAGE_SIZE, phys += PAGE_SIZE) {
		pte = pte_offset_kernel(pmd, virt);

		if (pte_none(*pte)) {
			pr_info("XX PTE %lx %pa[p]\n", virt, &phys);
			entry = pfn_pte(phys >> PAGE_SHIFT, prot);
			set_pte_at(&init_mm, virt, pte, entry);
		}
	}
}

static int add_pmd_pagetable(pud_t *pud, unsigned long virt, unsigned long end,
			     phys_addr_t phys, int node, pgprot_t prot)
{
	unsigned long next;
	pmd_t *pmd;
	void *p;

	while (virt < end) {
		next = pmd_addr_end(virt, end);
		pmd = pmd_offset(pud, virt);

		if (pmd_none(*pmd)) {
			if (next - virt >= PMD_SIZE) {
				pr_info("XX PMD %lx %pa[p]\n", virt, &phys);
				*pmd = pfn_pmd(phys >> PAGE_SHIFT, prot);
				goto next;
			} else {
				p = vmemmap_alloc_block_zero(PAGE_SIZE, node);
				if (!p)
					return -ENOMEM;
				pmd_populate_kernel(&init_mm, pmd, p);
			}
		}

		add_pte_pagetable(pmd, virt, next, phys, prot);

next:
		phys += next - virt;
		virt = next;
	}

	return 0;
}

static int add_pud_pagetable(p4d_t *p4d, unsigned long virt, unsigned long end,
			     phys_addr_t phys, int node, pgprot_t prot)
{
	unsigned long next;
	pud_t *pud;
	void *p;
	int ret;

	while (virt < end) {
		next = pud_addr_end(virt, end);
		pud = pud_offset(p4d, virt);

		if (pud_none(*pud)) {
			if (next - virt >= PUD_SIZE) {
				pr_info("XX PUD %lx %pa[p]\n", virt, &phys);
				*pud = pfn_pud(phys >> PAGE_SHIFT, prot);
				goto next;
			} else {
				p = vmemmap_alloc_block_zero(PAGE_SIZE, node);
				if (!p)
					return -ENOMEM;
				pud_populate(&init_mm, pud, p);
			}
		}

		ret = add_pmd_pagetable(pud, virt, next, phys, node, prot);
		if (ret)
			return ret;

next:
		phys += next - virt;
		virt = next;
	}

	return 0;
}

static int add_p4d_pagetable(pgd_t *pgd, unsigned long virt, unsigned long end,
			     phys_addr_t phys, int node, pgprot_t prot)
{
	unsigned long next;
	p4d_t *p4d;
	void *p;
	int ret;

	while (virt < end) {
		next = p4d_addr_end(virt, end);
		p4d = p4d_offset(pgd, virt);

		if (p4d_none(*p4d)) {
			if (next - virt >= P4D_SIZE) {
				pr_info("XX P4D %lx %pa[p]\n", virt, &phys);
				*p4d = pfn_p4d(phys >> PAGE_SHIFT, prot);
				goto next;
			} else {
				p = vmemmap_alloc_block_zero(PAGE_SIZE, node);
				if (!p)
					return -ENOMEM;
				p4d_populate(&init_mm, p4d, p);
			}
		}

		ret = add_pud_pagetable(p4d, virt, next, phys, node, prot);
		if (ret)
			return ret;

next:
		phys += next - virt;
		virt = next;
	}

	return 0;
}

static int __meminit add_pagetable(unsigned long virt, phys_addr_t phys,
				   unsigned long size, int node, pgprot_t prot)
{
	unsigned long end = virt + size;
	unsigned long next;
	pgd_t *pgd;
	void *p;
	int ret;

	while (virt < end) {
		next = pgd_addr_end(virt, end);
		pgd = pgd_offset_k(virt);

		if (pgd_none(*pgd)) {
			if (next - virt >= PGDIR_SIZE) {
				pr_info("XX PGD %lx %pa[p]\n", virt, &phys);
				*pgd = pfn_pgd(phys >> PAGE_SHIFT, prot);
				goto next;
			} else {
				p = vmemmap_alloc_block_zero(PAGE_SIZE, node);
				if (!p)
					return -ENOMEM;
				pgd_populate(&init_mm, pgd, p);
			}
		}

		ret = add_p4d_pagetable(pgd, virt, next, phys, node, prot);
		if (ret)
			return ret;

next:
		phys += next - virt;
		virt = next;
	}

	flush_tlb_all();

	return 0;
}

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

	ret = add_pagetable((unsigned long)__va(start), start, size, nid,
			    __pgprot(pgprot_val(PAGE_KERNEL) | _PAGE_EXEC));
	if (ret)
		return ret;

	ret = __add_pages(nid, start_pfn, nr_pages, altmap, want_memblock);
	WARN_ON_ONCE(ret);

	return ret;
}

#ifdef CONFIG_MEMORY_HOTREMOVE
int __ref arch_remove_memory(int nid, u64 start, u64 size,
			     struct vmem_altmap *altmap)
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
