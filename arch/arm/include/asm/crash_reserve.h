/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ARM_CRASH_RESERVE_H
#define _ARM_CRASH_RESERVE_H

/*
 * The crash region must be aligned to 128MB to avoid
 * zImage relocating below the reserved region.
 */
#define CRASH_ALIGN			(128 << 20)

#define CRASH_ADDR_LOW_MAX		crash_addr_low_max()
#define CRASH_ADDR_HIGH_MAX		memblock_end_of_DRAM()

static inline unsigned long crash_addr_low_max(void)
{
	unsigned long long crash_max = idmap_to_phys((u32)~0);
	unsigned long long lowmem_max = __pa(high_memory - 1) + 1;

	return (crash_max > lowmem_max) ? lowmem_max : crash_max;
}


#define HAVE_ARCH_ADD_CRASH_RES_TO_IOMEM_EARLY
#endif
