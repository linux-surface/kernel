// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 * Intel Precise Touch & Stylus
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2019 Dorian Stoll
 *
 */

#include <linux/acpi.h>
#include <linux/firmware.h>
#include <linux/ipts.h>
#include <linux/ipts-companion.h>
#include <linux/module.h>
#include <linux/platform_device.h>

#define IPTS_SURFACE_FW_PATH_FMT "intel/ipts/%s/%s"

/*
 * checkpatch complains about this and wants it wrapped with do { } while(0);
 * Since this would absolutely not work, just ignore checkpatch in this case.
 */
#define IPTS_SURFACE_FIRMWARE(X)					\
	MODULE_FIRMWARE("intel/ipts/" X "/config.bin");			\
	MODULE_FIRMWARE("intel/ipts/" X "/intel_desc.bin");		\
	MODULE_FIRMWARE("intel/ipts/" X "/vendor_desc.bin");		\
	MODULE_FIRMWARE("intel/ipts/" X "/vendor_kernel.bin")

struct ipts_surface_data {
	const char *hid;
	unsigned int quirks;
};

// Surface Book 1 / Surface Studio
static const struct ipts_surface_data ipts_surface_mshw0076 = {
	.hid = "MSHW0076",
	.quirks = IPTS_QUIRK_NO_FEEDBACK,
};

// Surface Pro 4
static const struct ipts_surface_data ipts_surface_mshw0078 = {
	.hid = "MSHW0078",
	.quirks = IPTS_QUIRK_NO_FEEDBACK,
};

// Surface Laptop 1 / 2
static const struct ipts_surface_data ipts_surface_mshw0079 = {
	.hid = "MSHW0079",
	.quirks = IPTS_QUIRK_NONE,
};

// Surface Pro 5 / 6
static const struct ipts_surface_data ipts_surface_mshw0101 = {
	.hid = "MSHW0101",
	.quirks = IPTS_QUIRK_NONE,
};

// Surface Book 2 15"
static const struct ipts_surface_data ipts_surface_mshw0102 = {
	.hid = "MSHW0102",
	.quirks = IPTS_QUIRK_NONE,
};

// Unknown, but firmware exists
static const struct ipts_surface_data ipts_surface_mshw0103 = {
	.hid = "MSHW0103",
	.quirks = IPTS_QUIRK_NONE,
};

// Surface Book 2 13"
static const struct ipts_surface_data ipts_surface_mshw0137 = {
	.hid = "MSHW0137",
	.quirks = IPTS_QUIRK_NONE,
};

/*
 * Checkpatch complains about the following lines because it sees them as
 * header files mixed with .c files. However, forward declaration is perfectly
 * fine in C, and this allows us to seperate the companion data from the
 * functions for the companion.
 */
int ipts_surface_request_firmware(struct ipts_companion *companion,
		const struct firmware **fw, const char *name,
		struct device *device);

unsigned int ipts_surface_get_quirks(struct ipts_companion *companion);

static struct ipts_bin_fw_info ipts_surface_vendor_kernel = {
	.fw_name = "vendor_kernel.bin",
	.vendor_output = -1,
	.num_of_data_files = 3,
	.data_file = {
		{
			.io_buffer_type = IPTS_CONFIGURATION,
			.flags = IPTS_DATA_FILE_FLAG_NONE,
			.file_name = "config.bin",
		},

		// The following files are part of the config, but they don't
		// exist, and the driver never requests them.
		{
			.io_buffer_type = IPTS_CALIBRATION,
			.flags = IPTS_DATA_FILE_FLAG_NONE,
			.file_name = "calib.bin",
		},
		{
			.io_buffer_type = IPTS_FEATURE,
			.flags = IPTS_DATA_FILE_FLAG_SHARE,
			.file_name = "feature.bin",
		},
	},
};

static struct ipts_bin_fw_info *ipts_surface_fw_config[] = {
	&ipts_surface_vendor_kernel,
	NULL,
};

static struct ipts_companion ipts_surface_companion = {
	.firmware_request = &ipts_surface_request_firmware,
	.firmware_config = ipts_surface_fw_config,
	.get_quirks = &ipts_surface_get_quirks,
	.name = "ipts_surface",
};

int ipts_surface_request_firmware(struct ipts_companion *companion,
		const struct firmware **fw, const char *name,
		struct device *device)
{
	char fw_path[MAX_IOCL_FILE_PATH_LEN];
	struct ipts_surface_data *data;

	if (companion == NULL || companion->data == NULL)
		return -ENOENT;

	data = (struct ipts_surface_data *)companion->data;

	snprintf(fw_path, MAX_IOCL_FILE_PATH_LEN, IPTS_SURFACE_FW_PATH_FMT,
		data->hid, name);
	return request_firmware(fw, fw_path, device);
}

unsigned int ipts_surface_get_quirks(struct ipts_companion *companion)
{
	struct ipts_surface_data *data;

	// In case something went wrong, assume that the
	// device doesn't have any quirks
	if (companion == NULL || companion->data == NULL)
		return IPTS_QUIRK_NONE;

	data = (struct ipts_surface_data *)companion->data;

	return data->quirks;
}

static int ipts_surface_probe(struct platform_device *pdev)
{
	int r;
	const struct ipts_surface_data *data =
		acpi_device_get_match_data(&pdev->dev);

	if (!data) {
		dev_err(&pdev->dev, "Unable to find ACPI info for device\n");
		return -ENODEV;
	}

	ipts_surface_companion.data = (void *)data;

	r = ipts_add_companion(&ipts_surface_companion);
	if (r) {
		dev_warn(&pdev->dev, "Adding IPTS companion failed: %d\n", r);
		return r;
	}

	return 0;
}

static int ipts_surface_remove(struct platform_device *pdev)
{
	int r = ipts_remove_companion(&ipts_surface_companion);

	if (r) {
		dev_warn(&pdev->dev, "Removing IPTS companion failed: %d\n", r);
		return r;
	}

	return 0;
}

static const struct acpi_device_id ipts_surface_acpi_match[] = {
	{ "MSHW0076", (unsigned long)&ipts_surface_mshw0076 },
	{ "MSHW0078", (unsigned long)&ipts_surface_mshw0078 },
	{ "MSHW0079", (unsigned long)&ipts_surface_mshw0079 },
	{ "MSHW0101", (unsigned long)&ipts_surface_mshw0101 },
	{ "MSHW0102", (unsigned long)&ipts_surface_mshw0102 },
	{ "MSHW0103", (unsigned long)&ipts_surface_mshw0103 },
	{ "MSHW0137", (unsigned long)&ipts_surface_mshw0137 },
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

IPTS_SURFACE_FIRMWARE("MSHW0076");
IPTS_SURFACE_FIRMWARE("MSHW0078");
IPTS_SURFACE_FIRMWARE("MSHW0079");
IPTS_SURFACE_FIRMWARE("MSHW0101");
IPTS_SURFACE_FIRMWARE("MSHW0102");
IPTS_SURFACE_FIRMWARE("MSHW0103");

IPTS_SURFACE_FIRMWARE("MSHW0137");
