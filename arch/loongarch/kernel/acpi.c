// SPDX-License-Identifier: GPL-2.0
/*
 * acpi.c - Architecture-Specific Low-Level ACPI Boot Support
 *
 * Author: Jianmin Lv <lvjianmin@loongson.cn>
 *         Huacai Chen <chenhuacai@loongson.cn>
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */

#include <linux/init.h>
#include <linux/acpi.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/memblock.h>
#include <linux/serial_core.h>
#include <asm/io.h>
#include <asm/loongson.h>

int acpi_disabled;
EXPORT_SYMBOL(acpi_disabled);
int acpi_noirq;
int acpi_pci_disabled;
EXPORT_SYMBOL(acpi_pci_disabled);
int acpi_strict = 1; /* We have no workarounds on LoongArch */
int num_processors;
int disabled_cpus;
enum acpi_irq_model_id acpi_irq_model = ACPI_IRQ_MODEL_PLATFORM;

u64 acpi_saved_sp;

#define MAX_CORE_PIC 256

#define PREFIX			"ACPI: "

int acpi_gsi_to_irq(u32 gsi, unsigned int *irqp)
{
	if (irqp != NULL)
		*irqp = acpi_register_gsi(NULL, gsi, -1, -1);
	return (*irqp >= 0) ? 0 : -EINVAL;
}
EXPORT_SYMBOL_GPL(acpi_gsi_to_irq);

int acpi_isa_irq_to_gsi(unsigned int isa_irq, u32 *gsi)
{
	if (gsi)
		*gsi = isa_irq;
	return 0;
}

/*
 * success: return IRQ number (>=0)
 * failure: return < 0
 */
int acpi_register_gsi(struct device *dev, u32 gsi, int trigger, int polarity)
{
	int id;
	struct irq_fwspec fwspec;

	switch (gsi) {
	case GSI_MIN_CPU_IRQ ... GSI_MAX_CPU_IRQ:
		fwspec.fwnode = liointc_domain->fwnode;
		fwspec.param[0] = gsi - GSI_MIN_CPU_IRQ;
		fwspec.param_count = 1;

		return irq_create_fwspec_mapping(&fwspec);

	case GSI_MIN_LPC_IRQ ... GSI_MAX_LPC_IRQ:
		if (!pch_lpc_domain)
			return -EINVAL;

		fwspec.fwnode = pch_lpc_domain->fwnode;
		fwspec.param[0] = gsi - GSI_MIN_LPC_IRQ;
		fwspec.param[1] = acpi_dev_get_irq_type(trigger, polarity);
		fwspec.param_count = 2;

		return irq_create_fwspec_mapping(&fwspec);

	case GSI_MIN_PCH_IRQ ... GSI_MAX_PCH_IRQ:
		id = find_pch_pic(gsi);
		if (id < 0)
			return -EINVAL;

		fwspec.fwnode = pch_pic_domain[id]->fwnode;
		fwspec.param[0] = gsi - acpi_pchpic[id]->gsi_base;
		fwspec.param[1] = IRQ_TYPE_LEVEL_HIGH;
		fwspec.param_count = 2;

		return irq_create_fwspec_mapping(&fwspec);
	}

	return -EINVAL;
}
EXPORT_SYMBOL_GPL(acpi_register_gsi);

void acpi_unregister_gsi(u32 gsi)
{

}
EXPORT_SYMBOL_GPL(acpi_unregister_gsi);

void __init __iomem * __acpi_map_table(unsigned long phys, unsigned long size)
{

	if (!phys || !size)
		return NULL;

	return early_memremap(phys, size);
}
void __init __acpi_unmap_table(void __iomem *map, unsigned long size)
{
	if (!map || !size)
		return;

	early_memunmap(map, size);
}

void __init __iomem *acpi_os_ioremap(acpi_physical_address phys, acpi_size size)
{
	if (!memblock_is_memory(phys))
		return ioremap(phys, size);
	else
		return ioremap_cache(phys, size);
}

void __init acpi_boot_table_init(void)
{
	/*
	 * If acpi_disabled, bail out
	 */
	if (acpi_disabled)
		return;

	/*
	 * Initialize the ACPI boot-time table parser.
	 */
	if (acpi_table_init()) {
		disable_acpi();
		return;
	}
}

static int __init
acpi_parse_cpuintc(union acpi_subtable_headers *header, const unsigned long end)
{
	struct acpi_madt_core_pic *processor = NULL;

	processor = (struct acpi_madt_core_pic *)header;
	if (BAD_MADT_ENTRY(processor, end))
		return -EINVAL;

	acpi_table_print_madt_entry(&header->common);

	return 0;
}

static int __init
acpi_parse_liointc(union acpi_subtable_headers *header, const unsigned long end)
{
	struct acpi_madt_lio_pic *liointc = NULL;

	liointc = (struct acpi_madt_lio_pic *)header;

	if (BAD_MADT_ENTRY(liointc, end))
		return -EINVAL;

	acpi_liointc = liointc;

	return 0;
}

static int __init
acpi_parse_eiointc(union acpi_subtable_headers *header, const unsigned long end)
{
	static int id = 0;
	struct acpi_madt_eio_pic *eiointc = NULL;

	eiointc = (struct acpi_madt_eio_pic *)header;

	if (BAD_MADT_ENTRY(eiointc, end))
		return -EINVAL;

	acpi_eiointc[id++] = eiointc;
	loongson_sysconf.nr_io_pics = id;

	return 0;
}

static int __init
acpi_parse_htintc(union acpi_subtable_headers *header, const unsigned long end)
{
	struct acpi_madt_ht_pic *htintc = NULL;

	htintc = (struct acpi_madt_ht_pic *)header;

	if (BAD_MADT_ENTRY(htintc, end))
		return -EINVAL;

	acpi_htintc = htintc;
	loongson_sysconf.nr_io_pics = 1;

	return 0;
}

static int __init
acpi_parse_pch_pic(union acpi_subtable_headers *header, const unsigned long end)
{
	static int id = 0;
	struct acpi_madt_bio_pic *pchpic = NULL;

	pchpic = (struct acpi_madt_bio_pic *)header;

	if (BAD_MADT_ENTRY(pchpic, end))
		return -EINVAL;

	acpi_pchpic[id++] = pchpic;

	return 0;
}

static int __init
acpi_parse_pch_msi(union acpi_subtable_headers *header, const unsigned long end)
{
	static int id = 0;
	struct acpi_madt_msi_pic *pchmsi = NULL;

	pchmsi = (struct acpi_madt_msi_pic *)header;

	if (BAD_MADT_ENTRY(pchmsi, end))
		return -EINVAL;

	acpi_pchmsi[id++] = pchmsi;

	return 0;
}

static int __init
acpi_parse_pch_lpc(union acpi_subtable_headers *header, const unsigned long end)
{
	struct acpi_madt_lpc_pic *pchlpc = NULL;

	pchlpc = (struct acpi_madt_lpc_pic *)header;

	if (BAD_MADT_ENTRY(pchlpc, end))
		return -EINVAL;

	acpi_pchlpc = pchlpc;

	return 0;
}

static void __init acpi_process_madt(void)
{
	int error;

	/* Parse MADT CPUINTC entries */
	error = acpi_table_parse_madt(ACPI_MADT_TYPE_CORE_PIC, acpi_parse_cpuintc, MAX_CORE_PIC);
	if (error < 0) {
		disable_acpi();
		pr_err(PREFIX "Invalid BIOS MADT (CPUINTC entries), ACPI disabled\n");
		return;
	}

	loongson_sysconf.nr_cpus = num_processors;

	/* Parse MADT LIOINTC entries */
	error = acpi_table_parse_madt(ACPI_MADT_TYPE_LIO_PIC, acpi_parse_liointc, 1);
	if (error < 0) {
		disable_acpi();
		pr_err(PREFIX "Invalid BIOS MADT (LIOINTC entries), ACPI disabled\n");
		return;
	}

	/* Parse MADT EIOINTC entries */
	error = acpi_table_parse_madt(ACPI_MADT_TYPE_EIO_PIC, acpi_parse_eiointc, MAX_IO_PICS);
	if (error < 0) {
		disable_acpi();
		pr_err(PREFIX "Invalid BIOS MADT (EIOINTC entries), ACPI disabled\n");
		return;
	}

	/* Parse MADT HTVEC entries */
	error = acpi_table_parse_madt(ACPI_MADT_TYPE_HT_PIC, acpi_parse_htintc, 1);
	if (error < 0) {
		disable_acpi();
		pr_err(PREFIX "Invalid BIOS MADT (HTVEC entries), ACPI disabled\n");
		return;
	}

	/* Parse MADT PCHPIC entries */
	error = acpi_table_parse_madt(ACPI_MADT_TYPE_BIO_PIC, acpi_parse_pch_pic, MAX_IO_PICS);
	if (error < 0) {
		disable_acpi();
		pr_err(PREFIX "Invalid BIOS MADT (PCHPIC entries), ACPI disabled\n");
		return;
	}

	/* Parse MADT PCHMSI entries */
	error = acpi_table_parse_madt(ACPI_MADT_TYPE_MSI_PIC, acpi_parse_pch_msi, MAX_IO_PICS);
	if (error < 0) {
		disable_acpi();
		pr_err(PREFIX "Invalid BIOS MADT (PCHMSI entries), ACPI disabled\n");
		return;
	}

	/* Parse MADT PCHLPC entries */
	error = acpi_table_parse_madt(ACPI_MADT_TYPE_LPC_PIC, acpi_parse_pch_lpc, 1);
	if (error < 0) {
		disable_acpi();
		pr_err(PREFIX "Invalid BIOS MADT (PCHLPC entries), ACPI disabled\n");
		return;
	}
}

int __init acpi_boot_init(void)
{
	/*
	 * If acpi_disabled, bail out
	 */
	if (acpi_disabled)
		return -1;

	loongson_sysconf.boot_cpu_id = read_csr_cpuid();

	/*
	 * Process the Multiple APIC Description Table (MADT), if present
	 */
	acpi_process_madt();

	/* Do not enable ACPI SPCR console by default */
	acpi_parse_spcr(earlycon_acpi_spcr_enable, false);

	return 0;
}

void __init arch_reserve_mem_area(acpi_physical_address addr, size_t size)
{
	memblock_reserve(addr, size);
}
