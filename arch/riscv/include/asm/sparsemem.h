/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __ASM_SPARSEMEM_H
#define __ASM_SPARSEMEM_H

#ifdef CONFIG_SPARSEMEM
#define MAX_PHYSMEM_BITS	CONFIG_PA_BITS
#define SECTION_SIZE_BITS	30
#endif

#endif
