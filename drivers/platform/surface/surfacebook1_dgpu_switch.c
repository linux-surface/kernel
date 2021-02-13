// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/module.h>
#include <linux/acpi.h>
#include <linux/platform_device.h>

/* MSHW0040/VGBI DSM UUID: 6fd05c69-cde3-49f4-95ed-ab1665498035 */
static const guid_t dgpu_sw_guid =
	GUID_INIT(0x6fd05c69, 0xcde3, 0x49f4,
		  0x95, 0xed, 0xab, 0x16, 0x65, 0x49, 0x80, 0x35);

#define DGPUSW_ACPI_PATH_DSM	"\\_SB_.PCI0.LPCB.EC0_.VGBI"
#define DGPUSW_ACPI_PATH_HGON	"\\_SB_.PCI0.RP05.HGON"
#define DGPUSW_ACPI_PATH_HGOF	"\\_SB_.PCI0.RP05.HGOF"

static int sb1_dgpu_sw_dsmcall(void)
{
	union acpi_object *obj;
	acpi_handle handle;
	acpi_status status;

	status = acpi_get_handle(NULL, DGPUSW_ACPI_PATH_DSM, &handle);
	if (status)
		return -EINVAL;

	obj = acpi_evaluate_dsm_typed(handle, &dgpu_sw_guid, 1, 1, NULL, ACPI_TYPE_BUFFER);
	if (!obj)
		return -EINVAL;

	ACPI_FREE(obj);
	return 0;
}

static int sb1_dgpu_sw_hgon(struct device *dev)
{
	struct acpi_buffer buf = {ACPI_ALLOCATE_BUFFER, NULL};
	acpi_status status;

	status = acpi_evaluate_object(NULL, DGPUSW_ACPI_PATH_HGON, NULL, &buf);
	if (status) {
		dev_err(dev, "failed to run HGON: %d\n", status);
		return -EINVAL;
	}

	ACPI_FREE(buf.pointer);

	dev_info(dev, "turned-on dGPU via HGON\n");
	return 0;
}

static int sb1_dgpu_sw_hgof(struct device *dev)
{
	struct acpi_buffer buf = {ACPI_ALLOCATE_BUFFER, NULL};
	acpi_status status;

	status = acpi_evaluate_object(NULL, DGPUSW_ACPI_PATH_HGOF, NULL, &buf);
	if (status) {
		dev_err(dev, "failed to run HGOF: %d\n", status);
		return -EINVAL;
	}

	ACPI_FREE(buf.pointer);

	dev_info(dev, "turned-off dGPU via HGOF\n");
	return 0;
}

static ssize_t dgpu_dsmcall_store(struct device *dev, struct device_attribute *attr,
				  const char *buf, size_t len)
{
	bool value;
	int status;

	status = kstrtobool(buf, &value);
	if (status < 0)
		return status;

	if (!value)
		return 0;

	status = sb1_dgpu_sw_dsmcall();

	return status < 0 ? status : len;
}
static DEVICE_ATTR_WO(dgpu_dsmcall);

static ssize_t dgpu_power_store(struct device *dev, struct device_attribute *attr,
				const char *buf, size_t len)
{
	bool power;
	int status;

	status = kstrtobool(buf, &power);
	if (status < 0)
		return status;

	if (power)
		status = sb1_dgpu_sw_hgon(dev);
	else
		status = sb1_dgpu_sw_hgof(dev);

	return status < 0 ? status : len;
}
static DEVICE_ATTR_WO(dgpu_power);

static struct attribute *sb1_dgpu_sw_attrs[] = {
	&dev_attr_dgpu_dsmcall.attr,
	&dev_attr_dgpu_power.attr,
	NULL
};
ATTRIBUTE_GROUPS(sb1_dgpu_sw);

/*
 * The dGPU power seems to be actually handled by MSHW0040. However, that is
 * also the power-/volume-button device with a mainline driver. So let's use
 * MSHW0041 instead for now, which seems to be the LTCH (latch/DTX) device.
 */
static const struct acpi_device_id sb1_dgpu_sw_match[] = {
	{ "MSHW0041", },
	{ }
};
MODULE_DEVICE_TABLE(acpi, sb1_dgpu_sw_match);

static struct platform_driver sb1_dgpu_sw = {
	.driver = {
		.name = "surfacebook1_dgpu_switch",
		.acpi_match_table = sb1_dgpu_sw_match,
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
		.dev_groups = sb1_dgpu_sw_groups,
	},
};
module_platform_driver(sb1_dgpu_sw);

MODULE_AUTHOR("Maximilian Luz <luzmaximilian@gmail.com>");
MODULE_DESCRIPTION("Discrete GPU Power-Switch for Surface Book 1");
MODULE_LICENSE("GPL");
