/*
 * NXP Wireless LAN device driver: PCIE and platform specific quirks
 *
 * This software file (the "File") is distributed by NXP
 * under the terms of the GNU General Public License Version 2, June 1991
 * (the "License").  You may use, redistribute and/or modify this File in
 * accordance with the terms and conditions of the License, a copy of which
 * is available by writing to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA or on the
 * worldwide web at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
 *
 * THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE
 * ARE EXPRESSLY DISCLAIMED.  The License provides additional details about
 * this warranty disclaimer.
 */

#include <linux/acpi.h>
#include <linux/dmi.h>

#include "pcie_quirks.h"

/* For reset_wsid quirk */
#define ACPI_WSID_PATH		"\\_SB.WSID"
#define WSID_REV		0x0
#define WSID_FUNC_WIFI_PWR_OFF	0x1
#define WSID_FUNC_WIFI_PWR_ON	0x2
/* WSID _DSM UUID: "534ea3bf-fcc2-4e7a-908f-a13978f0c7ef" */
static const guid_t wsid_dsm_guid =
	GUID_INIT(0x534ea3bf, 0xfcc2, 0x4e7a,
		  0x90, 0x8f, 0xa1, 0x39, 0x78, 0xf0, 0xc7, 0xef);

/* quirk table based on DMI matching */
static const struct dmi_system_id mwifiex_quirk_table[] = {
	{
		.ident = "Surface Pro 4",
		.matches = {
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "Microsoft Corporation"),
			DMI_EXACT_MATCH(DMI_PRODUCT_NAME, "Surface Pro 4"),
		},
		.driver_data = (void *)(QUIRK_FW_RST_D3COLD |
					QUIRK_NO_BRIDGE_D3 |
					QUIRK_DO_FLR_ON_BRIDGE),
	},
	{
		.ident = "Surface Pro 5",
		.matches = {
			/* match for SKU here due to generic product name "Surface Pro" */
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "Microsoft Corporation"),
			DMI_EXACT_MATCH(DMI_PRODUCT_SKU, "Surface_Pro_1796"),
		},
		.driver_data = (void *)(QUIRK_FW_RST_D3COLD |
					QUIRK_NO_BRIDGE_D3 |
					QUIRK_DO_FLR_ON_BRIDGE),
	},
	{
		.ident = "Surface Pro 5 (LTE)",
		.matches = {
			/* match for SKU here due to generic product name "Surface Pro" */
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "Microsoft Corporation"),
			DMI_EXACT_MATCH(DMI_PRODUCT_SKU, "Surface_Pro_1807"),
		},
		.driver_data = (void *)(QUIRK_FW_RST_D3COLD |
					QUIRK_NO_BRIDGE_D3 |
					QUIRK_DO_FLR_ON_BRIDGE),
	},
	{
		.ident = "Surface Pro 6",
		.matches = {
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "Microsoft Corporation"),
			DMI_EXACT_MATCH(DMI_PRODUCT_NAME, "Surface Pro 6"),
		},
		.driver_data = (void *)(QUIRK_FW_RST_D3COLD |
					QUIRK_NO_BRIDGE_D3 |
					QUIRK_DO_FLR_ON_BRIDGE),
	},
	{
		.ident = "Surface Book 1",
		.matches = {
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "Microsoft Corporation"),
			DMI_EXACT_MATCH(DMI_PRODUCT_NAME, "Surface Book"),
		},
		.driver_data = (void *)(QUIRK_FW_RST_D3COLD |
					QUIRK_NO_BRIDGE_D3 |
					QUIRK_DO_FLR_ON_BRIDGE),
	},
	{
		.ident = "Surface Book 2",
		.matches = {
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "Microsoft Corporation"),
			DMI_EXACT_MATCH(DMI_PRODUCT_NAME, "Surface Book 2"),
		},
		.driver_data = (void *)(QUIRK_FW_RST_D3COLD |
					QUIRK_NO_BRIDGE_D3 |
					QUIRK_DO_FLR_ON_BRIDGE),
	},
	{
		.ident = "Surface Laptop 1",
		.matches = {
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "Microsoft Corporation"),
			DMI_EXACT_MATCH(DMI_PRODUCT_NAME, "Surface Laptop"),
		},
		.driver_data = (void *)(QUIRK_FW_RST_D3COLD |
					QUIRK_NO_BRIDGE_D3 |
					QUIRK_DO_FLR_ON_BRIDGE),
	},
	{
		.ident = "Surface Laptop 2",
		.matches = {
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "Microsoft Corporation"),
			DMI_EXACT_MATCH(DMI_PRODUCT_NAME, "Surface Laptop 2"),
		},
		.driver_data = (void *)(QUIRK_FW_RST_D3COLD |
					QUIRK_NO_BRIDGE_D3 |
					QUIRK_DO_FLR_ON_BRIDGE),
	},
	{
		.ident = "Surface 3",
		.matches = {
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "Microsoft Corporation"),
			DMI_EXACT_MATCH(DMI_PRODUCT_NAME, "Surface 3"),
		},
		.driver_data = (void *)QUIRK_FW_RST_WSID_S3,
	},
	{
		.ident = "Surface 3",
		.matches = {
			DMI_EXACT_MATCH(DMI_BIOS_VENDOR, "American Megatrends Inc."),
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "OEMB"),
			DMI_EXACT_MATCH(DMI_PRODUCT_NAME, "OEMB"),
		},
		.driver_data = (void *)QUIRK_FW_RST_WSID_S3,
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
	if (card->quirks & QUIRK_FW_RST_D3COLD)
		dev_info(&pdev->dev, "quirk reset_d3cold enabled\n");
	if (card->quirks & QUIRK_FW_RST_WSID_S3)
		dev_info(&pdev->dev,
			 "quirk reset_wsid for Surface 3 enabled\n");
	if (card->quirks & QUIRK_NO_BRIDGE_D3)
		dev_info(&pdev->dev,
			 "quirk no_brigde_d3 enabled\n");
	if (card->quirks & QUIRK_DO_FLR_ON_BRIDGE)
		dev_info(&pdev->dev, "quirk do_flr_on_bridge enabled\n");
}

static void mwifiex_pcie_set_power_d3cold(struct pci_dev *pdev)
{
	dev_info(&pdev->dev, "putting into D3cold...\n");

	pci_save_state(pdev);
	if (pci_is_enabled(pdev))
		pci_disable_device(pdev);
	pci_set_power_state(pdev, PCI_D3cold);
}

static int mwifiex_pcie_set_power_d0(struct pci_dev *pdev)
{
	int ret;

	dev_info(&pdev->dev, "putting into D0...\n");

	pci_set_power_state(pdev, PCI_D0);
	ret = pci_enable_device(pdev);
	if (ret) {
		dev_err(&pdev->dev, "pci_enable_device failed\n");
		return ret;
	}
	pci_restore_state(pdev);

	return 0;
}

int mwifiex_pcie_reset_d3cold_quirk(struct pci_dev *pdev)
{
	struct pci_dev *parent_pdev = pci_upstream_bridge(pdev);
	int ret;

	/* Power-cycle (put into D3cold then D0) */
	dev_info(&pdev->dev, "Using reset_d3cold quirk to perform FW reset\n");

	/* We need to perform power-cycle also for bridge of wifi because
	 * on some devices (e.g. Surface Book 1), the OS for some reasons
	 * can't know the real power state of the bridge.
	 * When tried to power-cycle only wifi, the reset failed with the
	 * following dmesg log:
	 * "Cannot transition to power state D0 for parent in D3hot".
	 */
	mwifiex_pcie_set_power_d3cold(pdev);
	mwifiex_pcie_set_power_d3cold(parent_pdev);

	ret = mwifiex_pcie_set_power_d0(parent_pdev);
	if (ret)
		return ret;
	ret = mwifiex_pcie_set_power_d0(pdev);
	if (ret)
		return ret;

	return 0;
}

int mwifiex_pcie_reset_wsid_quirk(struct pci_dev *pdev)
{
	acpi_handle handle;
	union acpi_object *obj;
	acpi_status status;

	dev_info(&pdev->dev, "Using reset_wsid quirk to perform FW reset\n");

	status = acpi_get_handle(NULL, ACPI_WSID_PATH, &handle);
	if (ACPI_FAILURE(status)) {
		dev_err(&pdev->dev, "No ACPI handle for path %s\n",
			ACPI_WSID_PATH);
		return -ENODEV;
	}

	if (!acpi_has_method(handle, "_DSM")) {
		dev_err(&pdev->dev, "_DSM method not found\n");
		return -ENODEV;
	}

	if (!acpi_check_dsm(handle, &wsid_dsm_guid,
			    WSID_REV, WSID_FUNC_WIFI_PWR_OFF)) {
		dev_err(&pdev->dev,
			"_DSM method doesn't support wifi power off func\n");
		return -ENODEV;
	}

	if (!acpi_check_dsm(handle, &wsid_dsm_guid,
			    WSID_REV, WSID_FUNC_WIFI_PWR_ON)) {
		dev_err(&pdev->dev,
			"_DSM method doesn't support wifi power on func\n");
		return -ENODEV;
	}

	/* card will be removed immediately after this call on Surface 3 */
	dev_info(&pdev->dev, "turning wifi off...\n");
	obj = acpi_evaluate_dsm(handle, &wsid_dsm_guid,
				WSID_REV, WSID_FUNC_WIFI_PWR_OFF,
				NULL);
	if (!obj) {
		dev_err(&pdev->dev,
			"device _DSM execution failed for turning wifi off\n");
		return -EIO;
	}
	ACPI_FREE(obj);

	/* card will be re-probed immediately after this call on Surface 3 */
	dev_info(&pdev->dev, "turning wifi on...\n");
	obj = acpi_evaluate_dsm(handle, &wsid_dsm_guid,
				WSID_REV, WSID_FUNC_WIFI_PWR_ON,
				NULL);
	if (!obj) {
		dev_err(&pdev->dev,
			"device _DSM execution failed for turning wifi on\n");
		return -EIO;
	}
	ACPI_FREE(obj);

	return 0;
}
