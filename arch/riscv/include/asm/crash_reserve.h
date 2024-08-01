/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _RISCV_CRASH_RESERVE_H
#define _RISCV_CRASH_RESERVE_H

#define CRASH_ALIGN			PMD_SIZE

#define CRASH_ADDR_LOW_MAX		dma32_phys_limit
#define CRASH_ADDR_HIGH_MAX		memblock_end_of_DRAM()

#ifdef CONFIG_64BIT
#define HAVE_ARCH_CRASHKERNEL_RESERVATION_HIGH
#endif

extern phys_addr_t memblock_end_of_DRAM(void);
#endif
