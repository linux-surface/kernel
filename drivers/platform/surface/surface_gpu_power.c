// SPDX-License-Identifier: GPL-2.0+
/*
 * Surface GPU power controller driver.
 *
 * Surface Laptop Studio devices with a discrete NVIDIA GPU have an ACPI
 * "Surface IHV GPU Power Controller" device (MSHW0216). Its _DSM state
 * defaults to inactive, and while inactive the dGPU power resource sends
 * NVIDIA D-notify level D5 to the GPU on every power-on, i.e. after every
 * D3cold exit. This locks the GPU at a 10 W power limit. Windows avoids this
 * by activating the controller, which sends D1 (no restriction) instead and
 * prevents further D5 notifications. Do the same here.
 *
 * Activating the controller also disables Dynamic Boost in the NVPCF
 * parameters reported to the GPU driver, so re-enable it afterwards.
 *
 * Copyright (C) 2026 Danylo Dermenzhy <dvaderfun@gmail.com>
 */

#include <linux/acpi.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/pm.h>
#include <linux/unaligned.h>

/* a99df1bb-b888-42b7-9ced-12810bfe9d90 */
static const guid_t sgpc_dsm_guid =
	GUID_INIT(0xa99df1bb, 0xb888, 0x42b7, 0x9c, 0xed, 0x12, 0x81, 0x0b, 0xfe, 0x9d, 0x90);

#define SGPC_DSM_REVISION		0

enum sgpc_dsm_fn {
	SGPC_DSM_FN_SET_BOOST		= 0x01,
	SGPC_DSM_FN_GET_SPEC		= 0x05,
	SGPC_DSM_FN_SET_STATE		= 0x07,
};

enum sgpc_state {
	SGPC_STATE_INACTIVE		= 0,
	SGPC_STATE_ACTIVE		= 1,
};

static void sgpc_log_spec(struct device *dev)
{
	acpi_handle handle = ACPI_HANDLE(dev);
	union acpi_object *result;
	const u8 *buf;

	result = acpi_evaluate_dsm_typed(handle, &sgpc_dsm_guid, SGPC_DSM_REVISION,
					 SGPC_DSM_FN_GET_SPEC, NULL, ACPI_TYPE_BUFFER);
	if (!result) {
		dev_warn(dev, "failed to get GPU power specification\n");
		return;
	}

	if (result->buffer.length < 4 * sizeof(u32)) {
		dev_warn(dev, "unexpected GPU power specification length: %u\n",
			 result->buffer.length);
		goto out;
	}

	/* Layout: AC rated, AC max, DC rated, DC max; in watts. */
	buf = result->buffer.pointer;
	dev_info(dev, "GPU power specification: AC %u W (max %u W), DC %u W (max %u W)\n",
		 get_unaligned_le32(buf), get_unaligned_le32(buf + 4),
		 get_unaligned_le32(buf + 8), get_unaligned_le32(buf + 12));
out:
	ACPI_FREE(result);
}

static int sgpc_dsm_set(struct device *dev, enum sgpc_dsm_fn fn, u64 value)
{
	acpi_handle handle = ACPI_HANDLE(dev);
	union acpi_object *result;
	union acpi_object param;
	int status = 0;

	param.type = ACPI_TYPE_INTEGER;
	param.integer.value = value;

	result = acpi_evaluate_dsm_typed(handle, &sgpc_dsm_guid, SGPC_DSM_REVISION,
					 fn, &param, ACPI_TYPE_INTEGER);
	if (!result)
		return -EIO;

	if (result->integer.value != 0)
		status = -EIO;

	ACPI_FREE(result);
	return status;
}

static int sgpc_set_state(struct device *dev, enum sgpc_state state)
{
	int status;

	status = sgpc_dsm_set(dev, SGPC_DSM_FN_SET_STATE, state);
	if (status)
		dev_err(dev, "failed to set controller state to %d\n", state);

	return status;
}

static int sgpc_activate(struct device *dev)
{
	acpi_handle handle = ACPI_HANDLE(dev);
	int status;

	status = sgpc_set_state(dev, SGPC_STATE_ACTIVE);
	if (status)
		return status;

	/* Boost control only takes effect while the controller is active. */
	if (acpi_check_dsm(handle, &sgpc_dsm_guid, SGPC_DSM_REVISION,
			   BIT(SGPC_DSM_FN_SET_BOOST)) &&
	    sgpc_dsm_set(dev, SGPC_DSM_FN_SET_BOOST, 1))
		dev_warn(dev, "failed to enable Dynamic Boost\n");

	return 0;
}

static int surface_gpu_power_probe(struct platform_device *pdev)
{
	acpi_handle handle = ACPI_HANDLE(&pdev->dev);
	int status;

	if (!acpi_check_dsm(handle, &sgpc_dsm_guid, SGPC_DSM_REVISION,
			    BIT(SGPC_DSM_FN_SET_STATE)))
		return -ENODEV;

	if (acpi_check_dsm(handle, &sgpc_dsm_guid, SGPC_DSM_REVISION,
			   BIT(SGPC_DSM_FN_GET_SPEC)))
		sgpc_log_spec(&pdev->dev);

	status = sgpc_activate(&pdev->dev);
	if (status)
		return status;

	dev_dbg(&pdev->dev, "GPU power controller activated\n");
	return 0;
}

static void surface_gpu_power_remove(struct platform_device *pdev)
{
	/* Restore the firmware default. Note: This re-applies the 10 W limit. */
	sgpc_set_state(&pdev->dev, SGPC_STATE_INACTIVE);
}

static int surface_gpu_power_resume(struct device *dev)
{
	/*
	 * The state is kept in ACPI namespace and survives s2idle, but make
	 * sure it is still active in case firmware re-initialized it.
	 */
	return sgpc_activate(dev);
}

static DEFINE_SIMPLE_DEV_PM_OPS(surface_gpu_power_pm_ops, NULL, surface_gpu_power_resume);

static const struct acpi_device_id surface_gpu_power_acpi_match[] = {
	{ "MSHW0216", 0 },
	{ },
};
MODULE_DEVICE_TABLE(acpi, surface_gpu_power_acpi_match);

static struct platform_driver surface_gpu_power_driver = {
	.probe = surface_gpu_power_probe,
	.remove = surface_gpu_power_remove,
	.driver = {
		.name = "surface_gpu_power",
		.acpi_match_table = surface_gpu_power_acpi_match,
		.pm = pm_sleep_ptr(&surface_gpu_power_pm_ops),
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};
module_platform_driver(surface_gpu_power_driver);

MODULE_AUTHOR("Danylo Dermenzhy <dvaderfun@gmail.com>");
MODULE_DESCRIPTION("GPU Power Controller Driver for Surface Laptop Studio Devices");
MODULE_LICENSE("GPL");
