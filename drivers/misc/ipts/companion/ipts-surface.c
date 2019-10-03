#include <linux/acpi.h>
#include <linux/firmware.h>
#include <linux/intel_ipts_fw.h>
#include <linux/intel_ipts_if.h>
#include <linux/module.h>
#include <linux/platform_device.h>

#define IPTS_SURFACE_FW_PATH_FMT "intel/ipts/%s/%s"

#define __IPTS_SURFACE_FIRMWARE(X, Y)				\
	MODULE_FIRMWARE("intel/ipts/" X "/" Y)

#define IPTS_SURFACE_FIRMWARE(X)				\
	__IPTS_SURFACE_FIRMWARE(X, "config.bin");		\
	__IPTS_SURFACE_FIRMWARE(X, "intel_desc.bin");		\
	__IPTS_SURFACE_FIRMWARE(X, "intel_fw_config.bin");	\
	__IPTS_SURFACE_FIRMWARE(X, "vendor_desc.bin");		\
	__IPTS_SURFACE_FIRMWARE(X, "vendor_kernel.bin")

IPTS_SURFACE_FIRMWARE("MSHW0076");
IPTS_SURFACE_FIRMWARE("MSHW0078");
IPTS_SURFACE_FIRMWARE("MSHW0079");
IPTS_SURFACE_FIRMWARE("MSHW0101");
IPTS_SURFACE_FIRMWARE("MSHW0102");
IPTS_SURFACE_FIRMWARE("MSHW0103");
IPTS_SURFACE_FIRMWARE("MSHW0137");

int ipts_surface_request_firmware(const struct firmware **fw, const char *name,
	struct device *device, void *data)
{
	char fw_path[MAX_IOCL_FILE_PATH_LEN];

	if (data == NULL) {
		return -ENOENT;
	}

	snprintf(fw_path, MAX_IOCL_FILE_PATH_LEN, IPTS_SURFACE_FW_PATH_FMT,
		(const char *)data, name);
	return request_firmware(fw, fw_path, device);
}

static int ipts_surface_probe(struct platform_device *pdev)
{
	int ret;
	struct acpi_device *adev = ACPI_COMPANION(&pdev->dev);

	if (!adev) {
		dev_err(&pdev->dev, "Unable to find ACPI info for device\n");
		return -ENODEV;
	}

	ret = intel_ipts_add_fw_handler(&ipts_surface_request_firmware,
		(void *)acpi_device_hid(adev));
	if (ret) {
		dev_info(&pdev->dev, "Adding IPTS firmware handler failed, "
			"error: %d\n", ret);
		return ret;
	}

	return 0;
}

static int ipts_surface_remove(struct platform_device *pdev)
{
	int ret;

	ret = intel_ipts_rm_fw_handler(&ipts_surface_request_firmware);
	if (ret) {
		dev_info(&pdev->dev, "Removing IPTS firmware handler failed, "
			"error: %d\n", ret);
	}

	return 0;
}

static const struct acpi_device_id ipts_surface_acpi_match[] = {
	{ "MSHW0076", 0 },	/* Surface Book 1 / Surface Studio */
	{ "MSHW0078", 0 },	/* Surface Pro 4 */
	{ "MSHW0079", 0 },	/* Surface Laptop 1 / 2 */
	{ "MSHW0101", 0 },	/* Surface Book 2 15" */
	{ "MSHW0102", 0 },	/* Surface Pro 2017 / 6 */
	{ "MSHW0103", 0 },	/* unknown, but firmware exists */
	{ "MSHW0137", 0 },	/* Surface Book 2 */
	{ },
};
MODULE_DEVICE_TABLE(acpi, ipts_surface_acpi_match);

static struct platform_driver ipts_surface_driver = {
	.probe = ipts_surface_probe,
	.remove = ipts_surface_remove,
	.driver = {
		.name = "ipts_surface",
		.acpi_match_table = ACPI_PTR(ipts_surface_acpi_match),
	},
};
module_platform_driver(ipts_surface_driver);

MODULE_AUTHOR("Dorian Stoll <dorian.stoll@tmsp.io>");
MODULE_DESCRIPTION("IPTS companion driver for Microsoft Surface");
MODULE_LICENSE("GPL v2");
