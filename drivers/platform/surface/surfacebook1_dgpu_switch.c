// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/acpi.h>
#include <linux/platform_device.h>


#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) "%s:%s: " fmt, KBUILD_MODNAME, __func__


static const guid_t dgpu_sw_guid = GUID_INIT(0x6fd05c69, 0xcde3, 0x49f4,
	0x95, 0xed, 0xab, 0x16, 0x65, 0x49, 0x80, 0x35);

#define DGPUSW_ACPI_PATH_DSM	"\\_SB_.PCI0.LPCB.EC0_.VGBI"
#define DGPUSW_ACPI_PATH_HGON	"\\_SB_.PCI0.RP05.HGON"
#define DGPUSW_ACPI_PATH_HGOF	"\\_SB_.PCI0.RP05.HGOF"


static int sb1_dgpu_sw_dsmcall(void)
{
	union acpi_object *ret;
	acpi_handle handle;
	acpi_status status;

	status = acpi_get_handle(NULL, DGPUSW_ACPI_PATH_DSM, &handle);
	if (status)
		return -EINVAL;

	ret = acpi_evaluate_dsm_typed(handle, &dgpu_sw_guid, 1, 1, NULL, ACPI_TYPE_BUFFER);
	if (!ret)
		return -EINVAL;

	ACPI_FREE(ret);
	return 0;
}

static int sb1_dgpu_sw_hgon(void)
{
	struct acpi_buffer buf = {ACPI_ALLOCATE_BUFFER, NULL};
	acpi_status status;

	status = acpi_evaluate_object(NULL, DGPUSW_ACPI_PATH_HGON, NULL, &buf);
	if (status) {
		pr_err("failed to run HGON: %d\n", status);
		return -EINVAL;
	}

	if (buf.pointer)
		ACPI_FREE(buf.pointer);

	pr_info("turned-on dGPU via HGON\n");
	return 0;
}

static int sb1_dgpu_sw_hgof(void)
{
	struct acpi_buffer buf = {ACPI_ALLOCATE_BUFFER, NULL};
	acpi_status status;

	status = acpi_evaluate_object(NULL, DGPUSW_ACPI_PATH_HGOF, NULL, &buf);
	if (status) {
		pr_err("failed to run HGOF: %d\n", status);
		return -EINVAL;
	}

	if (buf.pointer)
		ACPI_FREE(buf.pointer);

	pr_info("turned-off dGPU via HGOF\n");
	return 0;
}


static ssize_t dgpu_dsmcall_store(struct device *dev, struct device_attribute *attr,
				  const char *buf, size_t len)
{
	int status, value;

	status = kstrtoint(buf, 0, &value);
	if (status < 0)
		return status;

	if (value != 1)
		return -EINVAL;

	status = sb1_dgpu_sw_dsmcall();

	return status < 0 ? status : len;
}

static ssize_t dgpu_power_store(struct device *dev, struct device_attribute *attr,
				const char *buf, size_t len)
{
	bool power;
	int status;

	status = kstrtobool(buf, &power);
	if (status < 0)
		return status;

	if (power)
		status = sb1_dgpu_sw_hgon();
	else
		status = sb1_dgpu_sw_hgof();

	return status < 0 ? status : len;
}

static DEVICE_ATTR_WO(dgpu_dsmcall);
static DEVICE_ATTR_WO(dgpu_power);

static struct attribute *sb1_dgpu_sw_attrs[] = {
	&dev_attr_dgpu_dsmcall.attr,
	&dev_attr_dgpu_power.attr,
	NULL,
};

static const struct attribute_group sb1_dgpu_sw_attr_group = {
	.attrs = sb1_dgpu_sw_attrs,
};


static int sb1_dgpu_sw_probe(struct platform_device *pdev)
{
	return sysfs_create_group(&pdev->dev.kobj, &sb1_dgpu_sw_attr_group);
}

static int sb1_dgpu_sw_remove(struct platform_device *pdev)
{
	sysfs_remove_group(&pdev->dev.kobj, &sb1_dgpu_sw_attr_group);
	return 0;
}

/*
 * The dGPU power seems to be actually handled by MSHW0040. However, that is
 * also the power-/volume-button device with a mainline driver. So let's use
 * MSHW0041 instead for now, which seems to be the LTCH (latch/DTX) device.
 */
static const struct acpi_device_id sb1_dgpu_sw_match[] = {
	{ "MSHW0041", },
	{ },
};
MODULE_DEVICE_TABLE(acpi, sb1_dgpu_sw_match);

static struct platform_driver sb1_dgpu_sw = {
	.probe = sb1_dgpu_sw_probe,
	.remove = sb1_dgpu_sw_remove,
	.driver = {
		.name = "surfacebook1_dgpu_switch",
		.acpi_match_table = sb1_dgpu_sw_match,
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};
module_platform_driver(sb1_dgpu_sw);

MODULE_AUTHOR("Maximilian Luz <luzmaximilian@gmail.com>");
MODULE_DESCRIPTION("Discrete GPU Power-Switch for Surface Book 1");
MODULE_LICENSE("GPL");
