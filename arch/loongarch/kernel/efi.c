// SPDX-License-Identifier: GPL-2.0
/*
 * EFI initialization
 *
 * Author: Jianmin Lv <lvjianmin@loongson.cn>
 *         Huacai Chen <chenhuacai@loongson.cn>
 *
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */

#include <linux/acpi.h>
#include <linux/efi.h>
#include <linux/efi-bgrt.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/io.h>
#include <linux/kobject.h>
#include <linux/memblock.h>
#include <linux/reboot.h>
#include <linux/uaccess.h>

#include <asm/early_ioremap.h>
#include <asm/efi.h>
#include <asm/tlb.h>
#include <asm/loongson.h>

static unsigned long efi_nr_tables;
static unsigned long efi_config_table;
static unsigned long screen_info_table __initdata = EFI_INVALID_TABLE_ADDR;

static efi_system_table_t *efi_systab;
static efi_config_table_type_t arch_tables[] __initdata = {
	{LINUX_EFI_LARCH_SCREEN_INFO_TABLE_GUID, &screen_info_table, "SINFO"},
	{},
};

static void __init init_screen_info(void)
{
	struct screen_info *si;

	if (screen_info_table == EFI_INVALID_TABLE_ADDR)
		return;

	si = early_memremap_ro(screen_info_table, sizeof(*si));
	if (!si) {
		pr_err("Could not map screen_info config table\n");
		return;
	}
	screen_info = *si;
	early_memunmap(si, sizeof(*si));

	if (screen_info.orig_video_isVGA == VIDEO_TYPE_EFI)
		memblock_reserve(screen_info.lfb_base, screen_info.lfb_size);
}

static void __init create_tlb(u32 index, u64 vppn, u32 ps, u32 mat)
{
	unsigned long tlblo0, tlblo1;

	write_csr_pagesize(ps);

	tlblo0 = vppn | CSR_TLBLO0_V | CSR_TLBLO0_WE |
		CSR_TLBLO0_GLOBAL | (mat << CSR_TLBLO0_CCA_SHIFT);
	tlblo1 = tlblo0 + (1 << ps);

	csr_write64(vppn, LOONGARCH_CSR_TLBEHI);
	csr_write64(tlblo0, LOONGARCH_CSR_TLBELO0);
	csr_write64(tlblo1, LOONGARCH_CSR_TLBELO1);
	csr_xchg32(0, CSR_TLBIDX_EHINV, LOONGARCH_CSR_TLBIDX);
	csr_xchg32(index, CSR_TLBIDX_IDX, LOONGARCH_CSR_TLBIDX);

	tlb_write_indexed();
}

#define MTLB_ENTRY_INDEX	0x800

/* Create VA == PA mapping as UEFI */
static void __init fix_efi_mapping(void)
{
	unsigned int index = MTLB_ENTRY_INDEX;
	unsigned int tlbnr = boot_cpu_data.tlbsizemtlb - 2;
	unsigned long i, vppn;

	/* Low Memory, Cached */
	create_tlb(index++, 0x00000000, PS_128M, 1);
	/* MMIO Registers, Uncached */
	create_tlb(index++, 0x10000000, PS_128M, 0);

	/* High Memory, Cached */
	for (i = 0; i < tlbnr; i++) {
		vppn = 0x80000000ULL + (i * SZ_2G);
		create_tlb(index++, vppn, PS_1G, 1);
	}
}

/*
 * set_virtual_map() - create a virtual mapping for the EFI memory map and call
 * efi_set_virtual_address_map enter virtual for runtime service
 *
 * This function populates the virt_addr fields of all memory region descriptors
 * in @memory_map whose EFI_MEMORY_RUNTIME attribute is set. Those descriptors
 * are also copied to @runtime_map, and their total count is returned in @count.
 */
static int __init set_virtual_map(void)
{
	int count = 0;
	unsigned int size;
	unsigned long attr;
	efi_status_t status;
	efi_runtime_services_t *rt;
	efi_set_virtual_address_map_t *svam;
	efi_memory_desc_t *in, runtime_map[32];

	size = sizeof(efi_memory_desc_t);

	for_each_efi_memory_desc(in) {
		attr = in->attribute;
		if (!(attr & EFI_MEMORY_RUNTIME))
			continue;

		if (attr & (EFI_MEMORY_WB | EFI_MEMORY_WT))
			in->virt_addr = TO_CACHE(in->phys_addr);
		else
			in->virt_addr = TO_UNCACHE(in->phys_addr);

		memcpy(&runtime_map[count++], in, size);
	}

	rt = early_memremap_ro((unsigned long)efi_systab->runtime, sizeof(*rt));

	/* Install the new virtual address map */
	svam = rt->set_virtual_address_map;

	fix_efi_mapping();

	status = svam(size * count, size, efi.memmap.desc_version,
			(efi_memory_desc_t *)TO_PHYS((unsigned long)runtime_map));

	local_flush_tlb_all();
	write_csr_pagesize(PS_DEFAULT_SIZE);

	return 0;
}

void __init efi_runtime_init(void)
{
	int status;

	if (!efi_enabled(EFI_BOOT))
		return;

	if (!efi_systab->runtime)
		return;

	status = set_virtual_map();
	if (status < 0)
		return;

	if (efi_runtime_disabled()) {
		pr_info("EFI runtime services will be disabled.\n");
		return;
	}

	efi.runtime = (efi_runtime_services_t *)efi_systab->runtime;
	efi.runtime_version = (unsigned int)efi.runtime->hdr.revision;

	efi_native_runtime_setup();
	set_bit(EFI_RUNTIME_SERVICES, &efi.flags);
}

void __init efi_init(void)
{
	int size;
	void *config_tables;

	if (!efi_system_table)
		return;

	efi_systab = (efi_system_table_t *)early_memremap_ro(efi_system_table, sizeof(*efi_systab));
	if (!efi_systab) {
		pr_err("Can't find EFI system table.\n");
		return;
	}

	set_bit(EFI_64BIT, &efi.flags);
	efi_nr_tables	 = efi_systab->nr_tables;
	efi_config_table = (unsigned long)efi_systab->tables;

	size = sizeof(efi_config_table_t);
	config_tables = early_memremap(efi_config_table, efi_nr_tables * size);
	efi_config_parse_tables(config_tables, efi_systab->nr_tables, arch_tables);
	early_memunmap(config_tables, efi_nr_tables * size);

	init_screen_info();
}
