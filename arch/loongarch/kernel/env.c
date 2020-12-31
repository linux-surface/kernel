// SPDX-License-Identifier: GPL-2.0
/*
 * Author: Huacai Chen <chenhuacai@loongson.cn>
 *
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */
#include <linux/acpi.h>
#include <linux/efi.h>
#include <linux/export.h>
#include <linux/memblock.h>
#include <linux/of_fdt.h>
#include <asm/early_ioremap.h>
#include <asm/bootinfo.h>
#include <asm/loongson.h>

u64 efi_system_table;
struct loongson_system_configuration loongson_sysconf;
EXPORT_SYMBOL(loongson_sysconf);

u64 loongson_chipcfg[MAX_PACKAGES];
u64 loongson_chiptemp[MAX_PACKAGES];
u64 loongson_freqctrl[MAX_PACKAGES];
unsigned long long smp_group[MAX_PACKAGES];

static void __init register_addrs_set(u64 *registers, const u64 addr, int num)
{
	u64 i;

	for (i = 0; i < num; i++) {
		*registers = (i << 44) | addr;
		registers++;
	}
}

void __init init_environ(void)
{
	int efi_boot = fw_arg0;
	struct efi_memory_map_data data;
	void *fdt_ptr = early_memremap_ro(fw_arg1, SZ_64K);

	if (efi_boot)
		set_bit(EFI_BOOT, &efi.flags);
	else
		clear_bit(EFI_BOOT, &efi.flags);

	early_init_dt_scan(fdt_ptr);
	early_init_fdt_reserve_self();
	efi_system_table = efi_get_fdt_params(&data);

	efi_memmap_init_early(&data);
	memblock_reserve(data.phys_map & PAGE_MASK,
			 PAGE_ALIGN(data.size + (data.phys_map & ~PAGE_MASK)));

	register_addrs_set(smp_group, TO_UNCACHE(0x1fe01000), 16);
	register_addrs_set(loongson_chipcfg, TO_UNCACHE(0x1fe00180), 16);
	register_addrs_set(loongson_chiptemp, TO_UNCACHE(0x1fe0019c), 16);
	register_addrs_set(loongson_freqctrl, TO_UNCACHE(0x1fe001d0), 16);
}

static int __init init_cpu_fullname(void)
{
	int cpu;

	if (loongson_sysconf.cpuname && !strncmp(loongson_sysconf.cpuname, "Loongson", 8)) {
		for (cpu = 0; cpu < NR_CPUS; cpu++)
			__cpu_full_name[cpu] = loongson_sysconf.cpuname;
	}
	return 0;
}
arch_initcall(init_cpu_fullname);
