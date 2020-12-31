/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */
#ifndef _ASM_PCI_H
#define _ASM_PCI_H

#include <linux/ioport.h>
#include <linux/list.h>
#include <linux/types.h>
#include <asm/io.h>

#define PCIBIOS_MIN_IO		0x4000
#define PCIBIOS_MIN_MEM		0x20000000
#define PCIBIOS_MIN_CARDBUS_IO	0x4000

#define HAVE_PCI_MMAP
#define ARCH_GENERIC_PCI_MMAP_RESOURCE

extern phys_addr_t mcfg_addr_init(int node);

static inline int pci_proc_domain(struct pci_bus *bus)
{
	return 1; /* always show the domain in /proc */
}

/*
 * Can be used to override the logic in pci_scan_bus for skipping
 * already-configured bus numbers - to be used for buggy BIOSes
 * or architectures with incomplete PCI setup by the loader
 */
static inline unsigned int pcibios_assign_all_busses(void)
{
	return 0;
}

/* generic pci stuff */
#include <asm-generic/pci.h>

#endif /* _ASM_PCI_H */
