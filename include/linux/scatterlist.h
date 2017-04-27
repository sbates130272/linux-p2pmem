#ifndef _LINUX_SCATTERLIST_H
#define _LINUX_SCATTERLIST_H

#include <linux/string.h>
#include <linux/types.h>
#include <linux/bug.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/pfn_t.h>
#include <asm/io.h>

struct scatterlist {
#ifdef CONFIG_DEBUG_SG
	unsigned long	sg_magic;
#endif
	pfn_t		pfn;
	unsigned int	offset;
	unsigned int	length;
	dma_addr_t	dma_address;
#ifdef CONFIG_NEED_SG_DMA_LENGTH
	unsigned int	dma_length;
#endif
};

/*
 * These macros should be used after a dma_map_sg call has been done
 * to get bus addresses of each of the SG entries and their lengths.
 * You should only work with the number of sg entries dma_map_sg
 * returns, or alternatively stop on the first sg_dma_len(sg) which
 * is 0.
 */
#define sg_dma_address(sg)	((sg)->dma_address)

#ifdef CONFIG_NEED_SG_DMA_LENGTH
#define sg_dma_len(sg)		((sg)->dma_length)
#else
#define sg_dma_len(sg)		((sg)->length)
#endif

struct sg_table {
	struct scatterlist *sgl;	/* the list */
	unsigned int nents;		/* number of mapped entries */
	unsigned int orig_nents;	/* original size of list */
};

/*
 * Notes on SG table design.
 *
 * We use the unsigned long page_link field in the scatterlist struct to place
 * the page pointer AND encode information about the sg table as well. The two
 * lower bits are reserved for this information.
 *
 * If bit 0 is set, then the page_link contains a pointer to the next sg
 * table list. Otherwise the next entry is at sg + 1.
 *
 * If bit 1 is set, then this sg entry is the last element in a list.
 *
 * See sg_next().
 *
 */

#define SG_MAGIC	0x87654321

static inline bool sg_is_chain(struct scatterlist *sg)
{
	return sg->pfn.val & PFN_SG_CHAIN;
}

static inline bool sg_is_last(struct scatterlist *sg)
{
	return sg->pfn.val & PFN_SG_LAST;
}

static inline struct scatterlist *sg_chain_ptr(struct scatterlist *sg)
{
	unsigned long sgl = pfn_t_to_pfn(sg->pfn);

	return (struct scatterlist *)(sgl << PAGE_SHIFT);
}

static inline bool sg_is_iomem(struct scatterlist *sg)
{
	return pfn_t_is_iomem(sg->pfn);
}

/**
 * sg_assign_pfn - Assign a given pfn_t to an SG entry
 * @sg:		    SG entry
 * @pfn:	    The pfn
 *
 * Description:
 *   Assign a pfn to sg entry. Also see sg_set_pfn(), the most commonly used
 *   variant.w
 *
 **/
static inline void sg_assign_pfn(struct scatterlist *sg, pfn_t pfn)
{
#ifdef CONFIG_DEBUG_SG
	BUG_ON(sg->sg_magic != SG_MAGIC);
	BUG_ON(sg_is_chain(sg));
	BUG_ON(pfn.val & (PFN_SG_CHAIN | PFN_SG_LAST));
#endif

	sg->pfn = pfn;
}

/**
 * sg_set_pfn - Set sg entry to point at given pfn
 * @sg:		 SG entry
 * @pfn:	 The page
 * @len:	 Length of data
 * @offset:	 Offset into page
 *
 * Description:
 *   Use this function to set an sg entry pointing at a pfn, never assign
 *   the page directly. We encode sg table information in the lower bits
 *   of the page pointer. See sg_pfn_t for looking up the pfn_t belonging
 *   to an sg entry.
 **/
static inline void sg_set_pfn(struct scatterlist *sg, pfn_t pfn,
			      unsigned int len, unsigned int offset)
{
	sg_assign_pfn(sg, pfn);
	sg->offset = offset;
	sg->length = len;
}

/**
 * sg_assign_page - Assign a given page to an SG entry
 * @sg:		    SG entry
 * @page:	    The page
 *
 * Description:
 *   Assign page to sg entry. Also see sg_set_page(), the most commonly used
 *   variant.
 *
 **/
static inline void sg_assign_page(struct scatterlist *sg, struct page *page)
{
	pfn_t null_pfn = {0};

	if (!page) {
		sg_assign_pfn(sg, null_pfn);
		return;
	}

	sg_assign_pfn(sg, page_to_pfn_t(page));
}

/**
 * sg_set_page - Set sg entry to point at given page
 * @sg:		 SG entry
 * @page:	 The page
 * @len:	 Length of data
 * @offset:	 Offset into page
 *
 * Description:
 *   Use this function to set an sg entry pointing at a page, never assign
 *   the page directly. We encode sg table information in the lower bits
 *   of the page pointer.
 *
 **/
static inline void sg_set_page(struct scatterlist *sg, struct page *page,
			       unsigned int len, unsigned int offset)
{
	sg_assign_page(sg, page);
	sg->offset = offset;
	sg->length = len;
}

/**
 * sg_pfn_t - Return the pfn_t for the sg
 * @sg:		 SG entry
 *
 **/
static inline pfn_t sg_pfn_t(struct scatterlist *sg)
{
#ifdef CONFIG_DEBUG_SG
	BUG_ON(sg->sg_magic != SG_MAGIC);
	BUG_ON(sg_is_chain(sg));
#endif

	return sg->pfn;
}

/**
 * sg_to_mappable_page - Try to return a struct page safe for general
 *	use in the kernel
 * @sg:		 SG entry
 * @page:	 A pointer to the returned page
 *
 * Description:
 *   If possible, return a mappable page that's safe for use around the
 *   kernel. Should only be used in legacy situations. sg_pfn_t() is a
 *   better choice for new code. This is deliberately more awkward than
 *   the old sg_page to enforce the __must_check rule and discourage future
 *   use.
 *
 *   An example where this is required is in nvme-fabrics: a page from an
 *   sgl is placed into a bio. This function would be required until we can
 *   convert bios to use pfn_t as well. Similar issues with skbs, etc.
 **/
static inline __must_check int sg_to_mappable_page(struct scatterlist *sg,
						   struct page **ret)
{
	struct page *pg;

	if (unlikely(sg_is_iomem(sg)))
		return -EFAULT;

	pg = pfn_t_to_page(sg->pfn);
	if (unlikely(!pg))
		return -EFAULT;

	*ret = pg;

	return 0;
}

#define SG_KMAP		     (1 << 0)	/* create a mapping with kmap */
#define SG_KMAP_ATOMIC	     (1 << 1)	/* create a mapping with kmap_atomic */
#define SG_MAP_MUST_NOT_FAIL (1 << 2)	/* indicate sg_map should not fail */

/**
 * sg_map - kmap a page inside an sgl
 * @sg:		SG entry
 * @offset:	Offset into entry
 * @flags:	Flags for creating the mapping
 *
 * Description:
 *   Use this function to map a page in the scatterlist at the specified
 *   offset. sg->offset is already added for you. Note: the semantics of
 *   this function are that it may fail. Thus, its output should be checked
 *   with IS_ERR and PTR_ERR. Otherwise, a pointer to the specified offset
 *   in the mapped page is returned.
 *
 *   Flags can be any of:
 *	* SG_KMAP		- Use kmap to create the mapping
 *	* SG_KMAP_ATOMIC	- Use kmap_atomic to map the page atommically.
 *				  Thus, the rules of that function apply: the
 *				  cpu may not sleep until it is unmaped.
 *	* SG_MAP_MUST_NOT_FAIL	- Indicate that sg_map must not fail.
 *				  If it does, it will issue a BUG_ON instead.
 *				  This is intended for legacy code only, it
 *				  is not to be used in new code.
 *
 *   Also, consider carefully whether this function is appropriate. It is
 *   largely not recommended for new code and if the sgl came from another
 *   subsystem and you don't know what kind of memory might be in the list
 *   then you definitely should not call it. Non-mappable memory may be in
 *   the sgl and thus this function may fail unexpectedly. Consider using
 *   sg_copy_to_buffer instead.
 **/
static inline void *sg_map(struct scatterlist *sg, size_t offset, int flags)
{
	struct page *pg;
	unsigned int pg_off;
	void *ret;

	if (unlikely(sg_is_iomem(sg))) {
		ret = ERR_PTR(-EFAULT);
		goto out;
	}

	pg = pfn_t_to_page(sg->pfn);
	if (unlikely(!pg)) {
		ret = ERR_PTR(-EFAULT);
		goto out;
	}

	offset += sg->offset;
	pg = nth_page(pg, offset >> PAGE_SHIFT);
	pg_off = offset_in_page(offset);

	if (flags & SG_KMAP_ATOMIC)
		ret = kmap_atomic(pg) + pg_off;
	else if (flags & SG_KMAP)
		ret = kmap(pg) + pg_off;
	else
		ret = ERR_PTR(-EINVAL);

out:
	BUG_ON(flags & SG_MAP_MUST_NOT_FAIL && IS_ERR(ret));

	return ret;
}

/**
 * sg_unmap - unmap a page that was mapped with sg_map_offset
 * @sg:		SG entry
 * @addr:	address returned by sg_map_offset
 * @offset:	Offset into entry (same as specified for sg_map)
 * @flags:	Flags, which are the same specified for sg_map
 *
 * Description:
 *   Unmap the page that was mapped with sg_map_offset
 **/
static inline void sg_unmap(struct scatterlist *sg, void *addr,
			    size_t offset, int flags)
{
	struct page *pg;
	unsigned int pg_off = offset_in_page(offset);

	pg = pfn_t_to_page(sg->pfn);
	if (unlikely(!pg))
		return;

	pg = nth_page(pg, offset >> PAGE_SHIFT);

	if (flags & SG_KMAP_ATOMIC)
		kunmap_atomic(addr - sg->offset - pg_off);
	else if (flags & SG_KMAP)
		kunmap(pg);
}

/**
 * sg_set_buf - Set sg entry to point at given data
 * @sg:		 SG entry
 * @buf:	 Data
 * @buflen:	 Data length
 *
 **/
static inline void sg_set_buf(struct scatterlist *sg, const void *buf,
			      unsigned int buflen)
{
#ifdef CONFIG_DEBUG_SG
	BUG_ON(!virt_addr_valid(buf));
#endif
	sg_set_page(sg, virt_to_page(buf), buflen, offset_in_page(buf));
}

/*
 * Loop over each sg element, following the pointer to a new list if necessary
 */
#define for_each_sg(sglist, sg, nr, __i)	\
	for (__i = 0, sg = (sglist); __i < (nr); __i++, sg = sg_next(sg))

/**
 * sg_chain - Chain two sglists together
 * @prv:	First scatterlist
 * @prv_nents:	Number of entries in prv
 * @sgl:	Second scatterlist
 *
 * Description:
 *   Links @prv@ and @sgl@ together, to form a longer scatterlist.
 *
 **/
static inline void sg_chain(struct scatterlist *prv, unsigned int prv_nents,
			    struct scatterlist *sgl)
{
	pfn_t pfn;
	unsigned long _sgl = (unsigned long)sgl;

	/*
	 * offset and length are unused for chain entry.  Clear them.
	 */
	prv[prv_nents - 1].offset = 0;
	prv[prv_nents - 1].length = 0;

	BUG_ON(_sgl & PAGE_MASK);
	pfn = __pfn_to_pfn_t(_sgl >> PAGE_SHIFT, PFN_SG_CHAIN);
	prv[prv_nents - 1].pfn = pfn;
}

/**
 * sg_mark_end - Mark the end of the scatterlist
 * @sg:		 SG entryScatterlist
 *
 * Description:
 *   Marks the passed in sg entry as the termination point for the sg
 *   table. A call to sg_next() on this entry will return NULL.
 *
 **/
static inline void sg_mark_end(struct scatterlist *sg)
{
#ifdef CONFIG_DEBUG_SG
	BUG_ON(sg->sg_magic != SG_MAGIC);
#endif
	/*
	 * Set termination bit, clear potential chain bit
	 */
	sg->pfn.val |= PFN_SG_LAST;
	sg->pfn.val &= ~PFN_SG_CHAIN;
}

/**
 * sg_unmark_end - Undo setting the end of the scatterlist
 * @sg:		 SG entryScatterlist
 *
 * Description:
 *   Removes the termination marker from the given entry of the scatterlist.
 *
 **/
static inline void sg_unmark_end(struct scatterlist *sg)
{
#ifdef CONFIG_DEBUG_SG
	BUG_ON(sg->sg_magic != SG_MAGIC);
#endif
	sg->pfn.val &= ~PFN_SG_LAST;
}

/**
 * sg_phys - Return physical address of an sg entry
 * @sg:	     SG entry
 *
 * Description:
 *   This calls pfn_t_to_phys() on the pfn in this sg entry, and adds the
 *   sg offset.
 *
 **/
static inline dma_addr_t sg_phys(struct scatterlist *sg)
{
	return pfn_t_to_phys(sg->pfn) + sg->offset;
}

/**
 * sg_virt - Return virtual address of an sg entry
 * @sg:      SG entry
 *
 * Description:
 *   This calls page_address() on the page in this sg entry, and adds the
 *   sg offset. The caller must know that the sg page has a valid virtual
 *   mapping.
 *
 **/
static inline void *sg_virt(struct scatterlist *sg)
{
	struct page *pg = pfn_t_to_page(sg->pfn);

	BUG_ON(sg_is_iomem(sg));
	BUG_ON(!pg);

	return page_address(pg) + sg->offset;
}

int sg_nents(struct scatterlist *sg);
int sg_nents_for_len(struct scatterlist *sg, u64 len);
struct scatterlist *sg_next(struct scatterlist *);
struct scatterlist *sg_last(struct scatterlist *s, unsigned int);
void sg_init_table(struct scatterlist *, unsigned int);
void sg_init_one(struct scatterlist *, const void *, unsigned int);
int sg_split(struct scatterlist *in, const int in_mapped_nents,
	     const off_t skip, const int nb_splits,
	     const size_t *split_sizes,
	     struct scatterlist **out, int *out_mapped_nents,
	     gfp_t gfp_mask);

typedef struct scatterlist *(sg_alloc_fn)(unsigned int, gfp_t);
typedef void (sg_free_fn)(struct scatterlist *, unsigned int);

void __sg_free_table(struct sg_table *, unsigned int, bool, sg_free_fn *);
void sg_free_table(struct sg_table *);
int __sg_alloc_table(struct sg_table *, unsigned int, unsigned int,
		     struct scatterlist *, gfp_t, sg_alloc_fn *);
int sg_alloc_table(struct sg_table *, unsigned int, gfp_t);
int sg_alloc_table_from_pages(struct sg_table *sgt,
	struct page **pages, unsigned int n_pages,
	unsigned long offset, unsigned long size,
	gfp_t gfp_mask);

size_t sg_copy_buffer(struct scatterlist *sgl, unsigned int nents, void *buf,
		      size_t buflen, off_t skip, bool to_buffer);

size_t sg_copy_from_buffer(struct scatterlist *sgl, unsigned int nents,
			   const void *buf, size_t buflen);
size_t sg_copy_to_buffer(struct scatterlist *sgl, unsigned int nents,
			 void *buf, size_t buflen);

size_t sg_pcopy_from_buffer(struct scatterlist *sgl, unsigned int nents,
			    const void *buf, size_t buflen, off_t skip);
size_t sg_pcopy_to_buffer(struct scatterlist *sgl, unsigned int nents,
			  void *buf, size_t buflen, off_t skip);

/*
 * Maximum number of entries that will be allocated in one piece, if
 * a list larger than this is required then chaining will be utilized.
 */
#define SG_MAX_SINGLE_ALLOC		(PAGE_SIZE / sizeof(struct scatterlist))

/*
 * The maximum number of SG segments that we will put inside a
 * scatterlist (unless chaining is used). Should ideally fit inside a
 * single page, to avoid a higher order allocation.  We could define this
 * to SG_MAX_SINGLE_ALLOC to pack correctly at the highest order.  The
 * minimum value is 32
 */
#define SG_CHUNK_SIZE	128

/*
 * Like SG_CHUNK_SIZE, but for archs that have sg chaining. This limit
 * is totally arbitrary, a setting of 2048 will get you at least 8mb ios.
 */
#ifdef CONFIG_ARCH_HAS_SG_CHAIN
#define SG_MAX_SEGMENTS	2048
#else
#define SG_MAX_SEGMENTS	SG_CHUNK_SIZE
#endif

#ifdef CONFIG_SG_POOL
void sg_free_table_chained(struct sg_table *table, bool first_chunk);
int sg_alloc_table_chained(struct sg_table *table, int nents,
			   struct scatterlist *first_chunk);
#endif

/*
 * sg page iterator
 *
 * Iterates over sg entries page-by-page.  On each successful iteration,
 * you can call sg_page_iter_page(@piter) and sg_page_iter_dma_address(@piter)
 * to get the current page and its dma address. @piter->sg will point to the
 * sg holding this page and @piter->sg_pgoffset to the page's page offset
 * within the sg. The iteration will stop either when a maximum number of sg
 * entries was reached or a terminating sg (sg_last(sg) == true) was reached.
 */
struct sg_page_iter {
	struct scatterlist	*sg;		/* sg holding the page */
	unsigned int		sg_pgoffset;	/* page offset within the sg */

	/* these are internal states, keep away */
	unsigned int		__nents;	/* remaining sg entries */
	int			__pg_advance;	/* nr pages to advance at the
						 * next step */
};

bool __sg_page_iter_next(struct sg_page_iter *piter);
void __sg_page_iter_start(struct sg_page_iter *piter,
			  struct scatterlist *sglist, unsigned int nents,
			  unsigned long pgoffset);
/**
 * sg_page_iter_page - get the current page held by the page iterator
 * @piter:	page iterator holding the page
 *
 * This function will require some cleanup. Some users simply mark
 * attributes of the pages which are fine, others actually map it and
 * will require some saftey there.
 */
static inline struct page *sg_page_iter_page(struct sg_page_iter *piter)
{
	struct page *pg = pfn_t_to_page(piter->sg->pfn);

	if (!pg)
		return NULL;

	return nth_page(pg, piter->sg_pgoffset);
}

/**
 * sg_page_iter_dma_address - get the dma address of the current page held by
 * the page iterator.
 * @piter:	page iterator holding the page
 */
static inline dma_addr_t sg_page_iter_dma_address(struct sg_page_iter *piter)
{
	return sg_dma_address(piter->sg) + (piter->sg_pgoffset << PAGE_SHIFT);
}

/**
 * for_each_sg_page - iterate over the pages of the given sg list
 * @sglist:	sglist to iterate over
 * @piter:	page iterator to hold current page, sg, sg_pgoffset
 * @nents:	maximum number of sg entries to iterate over
 * @pgoffset:	starting page offset
 */
#define for_each_sg_page(sglist, piter, nents, pgoffset)		   \
	for (__sg_page_iter_start((piter), (sglist), (nents), (pgoffset)); \
	     __sg_page_iter_next(piter);)

/*
 * Mapping sg iterator
 *
 * Iterates over sg entries mapping page-by-page.  On each successful
 * iteration, @miter->page points to the mapped page and
 * @miter->length bytes of data can be accessed at @miter->addr.  As
 * long as an interation is enclosed between start and stop, the user
 * is free to choose control structure and when to stop.
 *
 * @miter->consumed is set to @miter->length on each iteration.  It
 * can be adjusted if the user can't consume all the bytes in one go.
 * Also, a stopped iteration can be resumed by calling next on it.
 * This is useful when iteration needs to release all resources and
 * continue later (e.g. at the next interrupt).
 */

#define SG_MITER_ATOMIC		(1 << 0)	 /* use kmap_atomic */
#define SG_MITER_TO_SG		(1 << 1)	/* flush back to phys on unmap */
#define SG_MITER_FROM_SG	(1 << 2)	/* nop */
#define SG_MITER_SUPPORTS_IOMEM (1 << 3)        /* iteratee supports iomem */

struct sg_mapping_iter {
	/* the following three fields can be accessed directly */
	struct page		*page;		/* currently mapped page */
	void			*addr;		/* pointer to the mapped area */
	void __iomem            *ioaddr;        /* pointer iomem */
	size_t			length;		/* length of the mapped area */
	size_t			consumed;	/* number of consumed bytes */
	struct sg_page_iter	piter;		/* page iterator */

	/* these are internal states, keep away */
	unsigned int		__offset;	/* offset within page */
	unsigned int		__remaining;	/* remaining bytes on page */
	unsigned int		__flags;
};

void sg_miter_start(struct sg_mapping_iter *miter, struct scatterlist *sgl,
		    unsigned int nents, unsigned int flags);
bool sg_miter_skip(struct sg_mapping_iter *miter, off_t offset);
bool sg_miter_next(struct sg_mapping_iter *miter);
void sg_miter_stop(struct sg_mapping_iter *miter);

#endif /* _LINUX_SCATTERLIST_H */
