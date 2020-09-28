// SPDX-License-Identifier: GPL-2.0
/*
 * File for PCIe quirks.
 */

/* The low-level PCI operations will be performed in this file. Therefore,
 * let's use dev_*() instead of mwifiex_dbg() here to avoid troubles (e.g.
 * to avoid using mwifiex_adapter struct before init or wifi is powered
 * down, or causes NULL ptr deref).
 */

#include <linux/dmi.h>

#include "pcie_quirks.h"

/* quirk table based on DMI matching */
static const struct dmi_system_id mwifiex_quirk_table[] = {
	{
		.ident = "Surface Pro 4",
		.matches = {
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "Microsoft Corporation"),
			DMI_EXACT_MATCH(DMI_PRODUCT_NAME, "Surface Pro 4"),
		},
		.driver_data = 0,
	},
	{
		.ident = "Surface Pro 5",
		.matches = {
			/* match for SKU here due to generic product name "Surface Pro" */
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "Microsoft Corporation"),
			DMI_EXACT_MATCH(DMI_PRODUCT_SKU, "Surface_Pro_1796"),
		},
		.driver_data = 0,
	},
	{
		.ident = "Surface Pro 5 (LTE)",
		.matches = {
			/* match for SKU here due to generic product name "Surface Pro" */
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "Microsoft Corporation"),
			DMI_EXACT_MATCH(DMI_PRODUCT_SKU, "Surface_Pro_1807"),
		},
		.driver_data = 0,
	},
	{
		.ident = "Surface Pro 6",
		.matches = {
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "Microsoft Corporation"),
			DMI_EXACT_MATCH(DMI_PRODUCT_NAME, "Surface Pro 6"),
		},
		.driver_data = 0,
	},
	{
		.ident = "Surface Book 1",
		.matches = {
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "Microsoft Corporation"),
			DMI_EXACT_MATCH(DMI_PRODUCT_NAME, "Surface Book"),
		},
		.driver_data = 0,
	},
	{
		.ident = "Surface Book 2",
		.matches = {
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "Microsoft Corporation"),
			DMI_EXACT_MATCH(DMI_PRODUCT_NAME, "Surface Book 2"),
		},
		.driver_data = 0,
	},
	{
		.ident = "Surface Laptop 1",
		.matches = {
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "Microsoft Corporation"),
			DMI_EXACT_MATCH(DMI_PRODUCT_NAME, "Surface Laptop"),
		},
		.driver_data = 0,
	},
	{
		.ident = "Surface Laptop 2",
		.matches = {
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "Microsoft Corporation"),
			DMI_EXACT_MATCH(DMI_PRODUCT_NAME, "Surface Laptop 2"),
		},
		.driver_data = 0,
	},
	{
		.ident = "Surface 3",
		.matches = {
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "Microsoft Corporation"),
			DMI_EXACT_MATCH(DMI_PRODUCT_NAME, "Surface 3"),
		},
		.driver_data = 0,
	},
	{
		.ident = "Surface Pro 3",
		.matches = {
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "Microsoft Corporation"),
			DMI_EXACT_MATCH(DMI_PRODUCT_NAME, "Surface Pro 3"),
		},
		.driver_data = 0,
	},
	{}
};

void mwifiex_initialize_quirks(struct pcie_service_card *card)
{
	struct pci_dev *pdev = card->dev;
	const struct dmi_system_id *dmi_id;

	dmi_id = dmi_first_match(mwifiex_quirk_table);
	if (dmi_id)
		card->quirks = (uintptr_t)dmi_id->driver_data;

	if (!card->quirks)
		dev_info(&pdev->dev, "no quirks enabled\n");
}
