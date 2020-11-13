// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Surface GPE/Lid driver to enable wakeup from suspend via the lid by
 * properly configuring the respective GPEs. Required for wakeup via lid on
 * newer Intel-based Microsoft Surface devices.
 *
 * Copyright (C) 2020 Maximilian Luz <luzmaximilian@gmail.com>
 */

#include <linux/acpi.h>
#include <linux/dmi.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>


struct surface_lid_device {
	u32 gpe_number;
};

static const struct surface_lid_device lid_device_l17 = {
	.gpe_number = 0x17,
};

static const struct surface_lid_device lid_device_l4D = {
	.gpe_number = 0x4D,
};

static const struct surface_lid_device lid_device_l4F = {
	.gpe_number = 0x4F,
};

static const struct surface_lid_device lid_device_l57 = {
	.gpe_number = 0x57,
};


// Note: When changing this don't forget to change the MODULE_ALIAS below.
static const struct dmi_system_id dmi_lid_device_table[] = {
	{
		.ident = "Surface Pro 4",
		.matches = {
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "Microsoft Corporation"),
			DMI_EXACT_MATCH(DMI_PRODUCT_NAME, "Surface Pro 4"),
		},
		.driver_data = (void *)&lid_device_l17,
	},
	{
		.ident = "Surface Pro 5",
		.matches = {
			/*
			 * We match for SKU here due to generic product name
			 * "Surface Pro".
			 */
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "Microsoft Corporation"),
			DMI_EXACT_MATCH(DMI_PRODUCT_SKU, "Surface_Pro_1796"),
		},
		.driver_data = (void *)&lid_device_l4F,
	},
	{
		.ident = "Surface Pro 5 (LTE)",
		.matches = {
			/*
			 * We match for SKU here due to generic product name
			 * "Surface Pro"
			 */
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "Microsoft Corporation"),
			DMI_EXACT_MATCH(DMI_PRODUCT_SKU, "Surface_Pro_1807"),
		},
		.driver_data = (void *)&lid_device_l4F,
	},
	{
		.ident = "Surface Pro 6",
		.matches = {
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "Microsoft Corporation"),
			DMI_EXACT_MATCH(DMI_PRODUCT_NAME, "Surface Pro 6"),
		},
		.driver_data = (void *)&lid_device_l4F,
	},
	{
		.ident = "Surface Pro 7",
		.matches = {
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "Microsoft Corporation"),
			DMI_EXACT_MATCH(DMI_PRODUCT_NAME, "Surface Pro 7"),
		},
		.driver_data = (void *)&lid_device_l4D,
	},
	{
		.ident = "Surface Book 1",
		.matches = {
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "Microsoft Corporation"),
			DMI_EXACT_MATCH(DMI_PRODUCT_NAME, "Surface Book"),
		},
		.driver_data = (void *)&lid_device_l17,
	},
	{
		.ident = "Surface Book 2",
		.matches = {
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "Microsoft Corporation"),
			DMI_EXACT_MATCH(DMI_PRODUCT_NAME, "Surface Book 2"),
		},
		.driver_data = (void *)&lid_device_l17,
	},
	{
		.ident = "Surface Book 3",
		.matches = {
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "Microsoft Corporation"),
			DMI_EXACT_MATCH(DMI_PRODUCT_NAME, "Surface Book 3"),
		},
		.driver_data = (void *)&lid_device_l4D,
	},
	{
		.ident = "Surface Laptop 1",
		.matches = {
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "Microsoft Corporation"),
			DMI_EXACT_MATCH(DMI_PRODUCT_NAME, "Surface Laptop"),
		},
		.driver_data = (void *)&lid_device_l57,
	},
	{
		.ident = "Surface Laptop 2",
		.matches = {
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "Microsoft Corporation"),
			DMI_EXACT_MATCH(DMI_PRODUCT_NAME, "Surface Laptop 2"),
		},
		.driver_data = (void *)&lid_device_l57,
	},
	{
		.ident = "Surface Laptop 3 (Intel 13\")",
		.matches = {
			/*
			 * We match for SKU here due to different vairants: The
			 * AMD (15") version does not rely on GPEs.
			 */
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "Microsoft Corporation"),
			DMI_EXACT_MATCH(DMI_PRODUCT_SKU, "Surface_Laptop_3_1867:1868"),
		},
		.driver_data = (void *)&lid_device_l4D,
	},
	{
		.ident = "Surface Laptop 3 (Intel 15\")",
		.matches = {
			/*
			 * We match for SKU here due to different vairants: The
			 * AMD (15") version does not rely on GPEs.
			 */
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "Microsoft Corporation"),
			DMI_EXACT_MATCH(DMI_PRODUCT_SKU, "Surface_Laptop_3_1872"),
		},
		.driver_data = (void *)&lid_device_l4D,
	},
	{ }
};


static int surface_lid_enable_wakeup(struct device *dev,
				     const struct surface_lid_device *lid,
				     bool enable)
{
	int action = enable ? ACPI_GPE_ENABLE : ACPI_GPE_DISABLE;
	acpi_status status;

	status = acpi_set_gpe_wake_mask(NULL, lid->gpe_number, action);
	if (status) {
		dev_err(dev, "failed to set GPE wake mask: %d\n", status);
		return -EINVAL;
	}

	return 0;
}


static int surface_gpe_suspend(struct device *dev)
{
	const struct surface_lid_device *lid;

	lid = dev_get_platdata(dev);
	return surface_lid_enable_wakeup(dev, lid, true);
}

static int surface_gpe_resume(struct device *dev)
{
	const struct surface_lid_device *lid;

	lid = dev_get_platdata(dev);
	return surface_lid_enable_wakeup(dev, lid, false);
}

static SIMPLE_DEV_PM_OPS(surface_gpe_pm, surface_gpe_suspend, surface_gpe_resume);


static int surface_gpe_probe(struct platform_device *pdev)
{
	const struct surface_lid_device *lid;
	int status;

	lid = dev_get_platdata(&pdev->dev);
	if (!lid)
		return -ENODEV;

	status = acpi_mark_gpe_for_wake(NULL, lid->gpe_number);
	if (status) {
		dev_err(&pdev->dev, "failed to mark GPE for wake: %d\n", status);
		return -EINVAL;
	}

	status = acpi_enable_gpe(NULL, lid->gpe_number);
	if (status) {
		dev_err(&pdev->dev, "failed to enable GPE: %d\n", status);
		return -EINVAL;
	}

	status = surface_lid_enable_wakeup(&pdev->dev, lid, false);
	if (status) {
		acpi_disable_gpe(NULL, lid->gpe_number);
		return status;
	}

	return 0;
}

static int surface_gpe_remove(struct platform_device *pdev)
{
	struct surface_lid_device *lid = dev_get_platdata(&pdev->dev);

	/* restore default behavior without this module */
	surface_lid_enable_wakeup(&pdev->dev, lid, false);
	acpi_disable_gpe(NULL, lid->gpe_number);

	return 0;
}

static struct platform_driver surface_gpe_driver = {
	.probe = surface_gpe_probe,
	.remove = surface_gpe_remove,
	.driver = {
		.name = "surface_gpe",
		.pm = &surface_gpe_pm,
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};


static struct platform_device *surface_gpe_device;

static int __init surface_gpe_init(void)
{
	const struct dmi_system_id *match;
	const struct surface_lid_device *lid;
	struct platform_device *pdev;
	int status;

	match = dmi_first_match(dmi_lid_device_table);
	if (!match) {
		pr_info(KBUILD_MODNAME": no device detected, exiting\n");
		return 0;
	}

	lid = match->driver_data;

	status = platform_driver_register(&surface_gpe_driver);
	if (status)
		return status;

	pdev = platform_device_alloc("surface_gpe", PLATFORM_DEVID_NONE);
	if (!pdev) {
		platform_driver_unregister(&surface_gpe_driver);
		return -ENOMEM;
	}

	status = platform_device_add_data(pdev, lid, sizeof(*lid));
	if (status) {
		platform_device_put(pdev);
		platform_driver_unregister(&surface_gpe_driver);
		return status;
	}

	status = platform_device_add(pdev);
	if (status) {
		platform_device_put(pdev);
		platform_driver_unregister(&surface_gpe_driver);
		return status;
	}

	surface_gpe_device = pdev;
	return 0;
}

static void __exit surface_gpe_exit(void)
{
	if (!surface_gpe_device)
		return;

	platform_device_unregister(surface_gpe_device);
	platform_driver_unregister(&surface_gpe_driver);
}

module_init(surface_gpe_init);
module_exit(surface_gpe_exit);

MODULE_AUTHOR("Maximilian Luz <luzmaximilian@gmail.com>");
MODULE_DESCRIPTION("Surface GPE/Lid Driver");
MODULE_LICENSE("GPL");

MODULE_ALIAS("dmi:*:svnMicrosoftCorporation:pnSurfacePro:*");
MODULE_ALIAS("dmi:*:svnMicrosoftCorporation:pnSurfacePro4:*");
MODULE_ALIAS("dmi:*:svnMicrosoftCorporation:pnSurfacePro6:*");
MODULE_ALIAS("dmi:*:svnMicrosoftCorporation:pnSurfacePro7:*");
MODULE_ALIAS("dmi:*:svnMicrosoftCorporation:pnSurfaceBook:*");
MODULE_ALIAS("dmi:*:svnMicrosoftCorporation:pnSurfaceBook2:*");
MODULE_ALIAS("dmi:*:svnMicrosoftCorporation:pnSurfaceBook3:*");
MODULE_ALIAS("dmi:*:svnMicrosoftCorporation:pnSurfaceLaptop:*");
MODULE_ALIAS("dmi:*:svnMicrosoftCorporation:pnSurfaceLaptop2:*");
MODULE_ALIAS("dmi:*:svnMicrosoftCorporation:pnSurfaceLaptop3:*");
