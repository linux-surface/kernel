/*
 * Surface/System Integration Device (SID) driver.
 * Intended for device-dependent configuration and minor functionality.
 * Handles performance-modes and wakeup via lid open.
 */

#include <asm/unaligned.h>
#include <linux/acpi.h>
#include <linux/dmi.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/platform_device.h>
#include <linux/sysfs.h>

#include "surface_sam_ssh.h"


struct sid_lid_device {
	const char *acpi_path;
	const u32 gpe_number;
};

struct sid_device_info {
	const bool has_perf_mode;
	const struct sid_lid_device *lid_device;
};


static const struct sid_lid_device lid_device_l17 = {
	.acpi_path = "\\_SB.LID0",
	.gpe_number = 0x17,
};

static const struct sid_lid_device lid_device_l4F = {
	.acpi_path = "\\_SB.LID0",
	.gpe_number = 0x4F,
};

static const struct sid_lid_device lid_device_l57 = {
	.acpi_path = "\\_SB.LID0",
	.gpe_number = 0x57,
};


static const struct sid_device_info si_device_pro_4 = {
	.has_perf_mode = false,
	.lid_device = &lid_device_l17,
};

static const struct sid_device_info si_device_pro_5 = {
	.has_perf_mode = false,
	.lid_device = &lid_device_l4F,
};

static const struct sid_device_info si_device_pro_6 = {
	.has_perf_mode = false,
	.lid_device = &lid_device_l4F,
};

static const struct sid_device_info si_device_book_1 = {
	.has_perf_mode = false,
	.lid_device = &lid_device_l17,
};

static const struct sid_device_info si_device_book_2 = {
	.has_perf_mode = true,
	.lid_device = &lid_device_l17,
};

static const struct sid_device_info si_device_laptop_1 = {
	.has_perf_mode = false,
	.lid_device = &lid_device_l57,
};

static const struct sid_device_info si_device_laptop_2 = {
	.has_perf_mode = false,
	.lid_device = &lid_device_l57,
};


static const struct dmi_system_id dmi_lid_device_table[] = {
	{
		.ident = "Surface Pro 4",
		.matches = {
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "Microsoft Corporation"),
			DMI_EXACT_MATCH(DMI_PRODUCT_NAME, "Surface Pro 4"),
		},
		.driver_data = (void *)&si_device_pro_4,
	},
	{
		.ident = "Surface Pro 5",
		.matches = {
			/* match for SKU here due to generic product name "Surface Pro" */
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "Microsoft Corporation"),
			DMI_EXACT_MATCH(DMI_PRODUCT_SKU, "Surface_Pro_1796"),
		},
		.driver_data = (void *)&si_device_pro_5,
	},
	{
		.ident = "Surface Pro 5 (LTE)",
		.matches = {
			/* match for SKU here due to generic product name "Surface Pro" */
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "Microsoft Corporation"),
			DMI_EXACT_MATCH(DMI_PRODUCT_SKU, "Surface_Pro_1807"),
		},
		.driver_data = (void *)&si_device_pro_5,
	},
	{
		.ident = "Surface Pro 6",
		.matches = {
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "Microsoft Corporation"),
			DMI_EXACT_MATCH(DMI_PRODUCT_NAME, "Surface Pro 6"),
		},
		.driver_data = (void *)&si_device_pro_6,
	},
	{
		.ident = "Surface Book 1",
		.matches = {
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "Microsoft Corporation"),
			DMI_EXACT_MATCH(DMI_PRODUCT_NAME, "Surface Book"),
		},
		.driver_data = (void *)&si_device_book_1,
	},
	{
		.ident = "Surface Book 2",
		.matches = {
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "Microsoft Corporation"),
			DMI_EXACT_MATCH(DMI_PRODUCT_NAME, "Surface Book 2"),
		},
		.driver_data = (void *)&si_device_book_2,
	},
	{
		.ident = "Surface Laptop 1",
		.matches = {
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "Microsoft Corporation"),
			DMI_EXACT_MATCH(DMI_PRODUCT_NAME, "Surface Laptop"),
		},
		.driver_data = (void *)&si_device_laptop_1,
	},
	{
		.ident = "Surface Laptop 2",
		.matches = {
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "Microsoft Corporation"),
			DMI_EXACT_MATCH(DMI_PRODUCT_NAME, "Surface Laptop 2"),
		},
		.driver_data = (void *)&si_device_laptop_2,
	},
	{ }
};


#define SID_PARAM_PERM		(S_IRUGO | S_IWUSR)

enum sam_perf_mode {
	SAM_PERF_MODE_NORMAL   = 1,
	SAM_PERF_MODE_BATTERY  = 2,
	SAM_PERF_MODE_PERF1    = 3,
	SAM_PERF_MODE_PERF2    = 4,

	__SAM_PERF_MODE__START = 1,
	__SAM_PERF_MODE__END   = 4,
};

enum sid_param_perf_mode {
	SID_PARAM_PERF_MODE_AS_IS    = 0,
	SID_PARAM_PERF_MODE_NORMAL   = SAM_PERF_MODE_NORMAL,
	SID_PARAM_PERF_MODE_BATTERY  = SAM_PERF_MODE_BATTERY,
	SID_PARAM_PERF_MODE_PERF1    = SAM_PERF_MODE_PERF1,
	SID_PARAM_PERF_MODE_PERF2    = SAM_PERF_MODE_PERF2,

	__SID_PARAM_PERF_MODE__START = 0,
	__SID_PARAM_PERF_MODE__END   = 4,
};


static int surface_sam_perf_mode_get(void)
{
	u8 result_buf[8] = { 0 };
	int status;

	struct surface_sam_ssh_rqst rqst = {
		.tc  = 0x03,
		.iid = 0x00,
		.cid = 0x02,
		.snc = 0x01,
		.cdl = 0x00,
		.pld = NULL,
	};

	struct surface_sam_ssh_buf result = {
		.cap = ARRAY_SIZE(result_buf),
		.len = 0,
		.data = result_buf,
	};

	status = surface_sam_ssh_rqst(&rqst, &result);
	if (status) {
		return status;
	}

	if (result.len != 8) {
		return -EFAULT;
	}

	return get_unaligned_le32(&result.data[0]);
}

static int surface_sam_perf_mode_set(int perf_mode)
{
	u8 payload[4] = { 0 };

	struct surface_sam_ssh_rqst rqst = {
		.tc  = 0x03,
		.iid = 0x00,
		.cid = 0x03,
		.snc = 0x00,
		.cdl = ARRAY_SIZE(payload),
		.pld = payload,
	};

	if (perf_mode < __SAM_PERF_MODE__START || perf_mode > __SAM_PERF_MODE__END) {
		return -EINVAL;
	}

	put_unaligned_le32(perf_mode, &rqst.pld[0]);
	return surface_sam_ssh_rqst(&rqst, NULL);
}


static int param_perf_mode_set(const char *val, const struct kernel_param *kp)
{
	int perf_mode;
	int status;

	status = kstrtoint(val, 0, &perf_mode);
	if (status) {
		return status;
	}

	if (perf_mode < __SID_PARAM_PERF_MODE__START || perf_mode > __SID_PARAM_PERF_MODE__END) {
		return -EINVAL;
	}

	return param_set_int(val, kp);
}

static const struct kernel_param_ops param_perf_mode_ops = {
	.set = param_perf_mode_set,
	.get = param_get_int,
};

static int param_perf_mode_init = SID_PARAM_PERF_MODE_AS_IS;
static int param_perf_mode_exit = SID_PARAM_PERF_MODE_AS_IS;

module_param_cb(perf_mode_init, &param_perf_mode_ops, &param_perf_mode_init, SID_PARAM_PERM);
module_param_cb(perf_mode_exit, &param_perf_mode_ops, &param_perf_mode_exit, SID_PARAM_PERM);

MODULE_PARM_DESC(perf_mode_init, "Performance-mode to be set on module initialization");
MODULE_PARM_DESC(perf_mode_exit, "Performance-mode to be set on module exit");


static ssize_t perf_mode_show(struct device *dev, struct device_attribute *attr, char *data)
{
	int perf_mode;

	perf_mode = surface_sam_perf_mode_get();
	if (perf_mode < 0) {
		dev_err(dev, "failed to get current performance mode: %d", perf_mode);
		return -EIO;
	}

	return sprintf(data, "%d\n", perf_mode);
}

static ssize_t perf_mode_store(struct device *dev, struct device_attribute *attr,
                               const char *data, size_t count)
{
	int perf_mode;
	int status;

	status = kstrtoint(data, 0, &perf_mode);
	if (status) {
		return status;
	}

	status = surface_sam_perf_mode_set(perf_mode);
	if (status) {
		return status;
	}

	// TODO: Should we notify ACPI here?
	//
	//       There is a _DSM call described as
	//           WSID._DSM: Notify DPTF on Slider State change
	//       which calls
	//           ODV3 = ToInteger (Arg3)
	//           Notify(IETM, 0x88)
	//       IETM is an INT3400 Intel Dynamic Power Performance Management
	//       device, part of the DPTF framework. From the corresponding
	//       kernel driver, it looks like event 0x88 is being ignored. Also
	//       it is currently unknown what the consequecnes of setting ODV3
	//       are.

	return count;
}

const static DEVICE_ATTR_RW(perf_mode);


static int sid_perf_mode_setup(struct platform_device *pdev, const struct sid_device_info *info)
{
	int status;

	if (!info->has_perf_mode)
		return 0;

	// link to ec
	status = surface_sam_ssh_consumer_register(&pdev->dev);
	if (status) {
		return status == -ENXIO ? -EPROBE_DEFER : status;
	}

	// set initial perf_mode
	if (param_perf_mode_init != SID_PARAM_PERF_MODE_AS_IS) {
		status = surface_sam_perf_mode_set(param_perf_mode_init);
		if (status) {
			return status;
		}
	}

	// register perf_mode attribute
	status = sysfs_create_file(&pdev->dev.kobj, &dev_attr_perf_mode.attr);
	if (status) {
		goto err_sysfs;
	}

	return 0;

err_sysfs:
	surface_sam_perf_mode_set(param_perf_mode_exit);
	return status;
}

static void sid_perf_mode_remove(struct platform_device *pdev, const struct sid_device_info *info)
{
	if (!info->has_perf_mode)
		return;

	// remove perf_mode attribute
	sysfs_remove_file(&pdev->dev.kobj, &dev_attr_perf_mode.attr);

	// set exit perf_mode
	surface_sam_perf_mode_set(param_perf_mode_exit);
}


static int sid_lid_enable_wakeup(const struct sid_device_info *info, bool enable)
{
	int action = enable ? ACPI_GPE_ENABLE : ACPI_GPE_DISABLE;
	int status;

	if (!info->lid_device)
		return 0;

	status = acpi_set_gpe_wake_mask(NULL, info->lid_device->gpe_number, action);
	if (status)
		return -EFAULT;

	return 0;
}

static int sid_lid_device_setup(const struct sid_device_info *info)
{
	acpi_handle lid_handle;
	int status;

	if (!info->lid_device)
		return 0;

	status = acpi_get_handle(NULL, (acpi_string)info->lid_device->acpi_path, &lid_handle);
	if (status)
		return -EFAULT;

	status = acpi_setup_gpe_for_wake(lid_handle, NULL, info->lid_device->gpe_number);
	if (status)
		return -EFAULT;

	status = acpi_enable_gpe(NULL, info->lid_device->gpe_number);
	if (status)
		return -EFAULT;

	return sid_lid_enable_wakeup(info, false);
}

static void sid_lid_device_remove(const struct sid_device_info *info)
{
	/* restore default behavior without this module */
	sid_lid_enable_wakeup(info, false);
}


static int surface_sam_sid_suspend(struct device *dev)
{
	const struct sid_device_info *info = dev_get_drvdata(dev);
	return sid_lid_enable_wakeup(info, true);
}

static int surface_sam_sid_resume(struct device *dev)
{
	const struct sid_device_info *info = dev_get_drvdata(dev);
	return sid_lid_enable_wakeup(info, false);
}

static SIMPLE_DEV_PM_OPS(surface_sam_sid_pm, surface_sam_sid_suspend, surface_sam_sid_resume);


static int surface_sam_sid_probe(struct platform_device *pdev)
{
	const struct dmi_system_id *dmi_match;
	struct sid_device_info *info;
	int status;

	dmi_match = dmi_first_match(dmi_lid_device_table);
	if (!dmi_match)
		return -ENODEV;

	info = dmi_match->driver_data;

	platform_set_drvdata(pdev, info);

	status = sid_perf_mode_setup(pdev, info);
	if (status)
		goto err_perf_mode;

	status = sid_lid_device_setup(info);
	if (status)
		goto err_lid;

	return 0;

err_lid:
	sid_perf_mode_remove(pdev, info);
err_perf_mode:
	return status;
}

static int surface_sam_sid_remove(struct platform_device *pdev)
{
	const struct sid_device_info *info = platform_get_drvdata(pdev);

	sid_perf_mode_remove(pdev, info);
	sid_lid_device_remove(info);

	platform_set_drvdata(pdev, NULL);
	return 0;
}


static const struct acpi_device_id surface_sam_sid_match[] = {
	{ "MSHW0081", },	/* Surface Pro 4, 5, and 6 */
	{ "MSHW0080", },	/* Surface Book 1 */
	{ "MSHW0107", },	/* Surface Book 2 */
	{ "MSHW0086", },	/* Surface Laptop 1 */
	{ "MSHW0112", },	/* Surface Laptop 2 */
	{ },
};
MODULE_DEVICE_TABLE(acpi, surface_sam_sid_match);

struct platform_driver surface_sam_sid = {
	.probe = surface_sam_sid_probe,
	.remove = surface_sam_sid_remove,
	.driver = {
		.name = "surface_sam_sid",
		.acpi_match_table = ACPI_PTR(surface_sam_sid_match),
		.pm = &surface_sam_sid_pm,
	},
};
module_platform_driver(surface_sam_sid);

MODULE_AUTHOR("Maximilian Luz <luzmaximilian@gmail.com>");
MODULE_DESCRIPTION("Surface Integration Driver for 5th Generation Surface Devices");
MODULE_LICENSE("GPL v2");
