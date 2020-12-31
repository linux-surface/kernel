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
#include <asm/numa.h>
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

static int set_processor_mask(u32 id, u32 flags)
{

	int cpu, cpuid = id;

	if (num_processors >= nr_cpu_ids) {
		pr_warn(PREFIX "nr_cpus/possible_cpus limit of %i reached."
			" processor 0x%x ignored.\n", nr_cpu_ids, cpuid);

		return -ENODEV;

	}
	if (cpuid == loongson_sysconf.boot_cpu_id)
		cpu = 0;
	else
		cpu = cpumask_next_zero(-1, cpu_present_mask);

	if (flags & ACPI_MADT_ENABLED) {
		num_processors++;
		set_cpu_possible(cpu, true);
		set_cpu_present(cpu, true);
		__cpu_number_map[cpuid] = cpu;
		__cpu_logical_map[cpu] = cpuid;
	} else
		disabled_cpus++;

	return cpu;
}

static int __init
acpi_parse_cpuintc(union acpi_subtable_headers *header, const unsigned long end)
{
	struct acpi_madt_core_pic *processor = NULL;

	processor = (struct acpi_madt_core_pic *)header;
	if (BAD_MADT_ENTRY(processor, end))
		return -EINVAL;

	acpi_table_print_madt_entry(&header->common);
	set_processor_mask(processor->core_id, processor->flags);

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
	int i, error;

	for (i = 0; i < NR_CPUS; i++) {
		__cpu_number_map[i] = -1;
		__cpu_logical_map[i] = -1;
	}

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

#ifdef CONFIG_ACPI_NUMA

static __init int setup_node(int pxm)
{
	return acpi_map_pxm_to_node(pxm);
}

/*
 * Callback for SLIT parsing.  pxm_to_node() returns NUMA_NO_NODE for
 * I/O localities since SRAT does not list them.  I/O localities are
 * not supported at this point.
 */
unsigned int numa_distance_cnt;

static inline unsigned int get_numa_distances_cnt(struct acpi_table_slit *slit)
{
	return slit->locality_count;
}

void __init numa_set_distance(int from, int to, int distance)
{
	if ((u8)distance != distance || (from == to && distance != LOCAL_DISTANCE)) {
		pr_warn_once("Warning: invalid distance parameter, from=%d to=%d distance=%d\n",
				from, to, distance);
		return;
	}

	node_distances[from][to] = distance;
}

/* Callback for Proximity Domain -> CPUID mapping */
void __init
acpi_numa_processor_affinity_init(struct acpi_srat_cpu_affinity *pa)
{
	int pxm, node;

	if (srat_disabled())
		return;
	if (pa->header.length != sizeof(struct acpi_srat_cpu_affinity)) {
		bad_srat();
		return;
	}
	if ((pa->flags & ACPI_SRAT_CPU_ENABLED) == 0)
		return;
	pxm = pa->proximity_domain_lo;
	if (acpi_srat_revision >= 2) {
		pxm |= (pa->proximity_domain_hi[0] << 8);
		pxm |= (pa->proximity_domain_hi[1] << 16);
		pxm |= (pa->proximity_domain_hi[2] << 24);
	}
	node = setup_node(pxm);
	if (node < 0) {
		pr_err("SRAT: Too many proximity domains %x\n", pxm);
		bad_srat();
		return;
	}

	if (pa->apic_id >= CONFIG_NR_CPUS) {
		pr_info("SRAT: PXM %u -> CPU 0x%02x -> Node %u skipped apicid that is too big\n",
				pxm, pa->apic_id, node);
		return;
	}

	early_numa_add_cpu(pa->apic_id, node);

	set_cpuid_to_node(pa->apic_id, node);
	node_set(node, numa_nodes_parsed);
	pr_info("SRAT: PXM %u -> CPU 0x%02x -> Node %u\n", pxm, pa->apic_id, node);
}

void __init acpi_numa_arch_fixup(void) {}
#endif

void __init arch_reserve_mem_area(acpi_physical_address addr, size_t size)
{
	memblock_reserve(addr, size);
}

#ifdef CONFIG_ACPI_HOTPLUG_CPU

#include <acpi/processor.h>

static int __ref acpi_map_cpu2node(acpi_handle handle, int cpu, int physid)
{
#ifdef CONFIG_ACPI_NUMA
	int nid;

	nid = acpi_get_node(handle);
	if (nid != NUMA_NO_NODE) {
		set_cpuid_to_node(physid, nid);
		node_set(nid, numa_nodes_parsed);
		set_cpu_numa_node(cpu, nid);
		cpumask_set_cpu(cpu, cpumask_of_node(nid));
	}
#endif
	return 0;
}

int acpi_map_cpu(acpi_handle handle, phys_cpuid_t physid, u32 acpi_id, int *pcpu)
{
	int cpu;

	cpu = set_processor_mask(physid, ACPI_MADT_ENABLED);
	if (cpu < 0) {
		pr_info(PREFIX "Unable to map lapic to logical cpu number\n");
		return cpu;
	}

	acpi_map_cpu2node(handle, cpu, physid);

	*pcpu = cpu;

	return 0;
}
EXPORT_SYMBOL(acpi_map_cpu);

int acpi_unmap_cpu(int cpu)
{
#ifdef CONFIG_ACPI_NUMA
	set_cpuid_to_node(cpu_logical_map(cpu), NUMA_NO_NODE);
#endif
	set_cpu_present(cpu, false);
	num_processors--;

	pr_info("cpu%d hot remove!\n", cpu);

	return 0;
}
EXPORT_SYMBOL(acpi_unmap_cpu);

#endif /* CONFIG_ACPI_HOTPLUG_CPU */
