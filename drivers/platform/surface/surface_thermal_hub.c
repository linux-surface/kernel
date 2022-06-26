// SPDX-License-Identifier: GPL-2.0+
/*
 * Thermal sensor hub driver for Surface System Aggregator Module (SSAM).
 *
 * Provides a hub device for automatic instantiation of thermal sensor
 * (child-)devices.
 *
 * Copyright (C) 2022 Maximilian Luz <luzmaximilian@gmail.com>
 */

#include <asm/unaligned.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>

#include <linux/surface_aggregator/controller.h>
#include <linux/surface_aggregator/device.h>

#define SSAM_TMP_MAX_SENSORS	16

SSAM_DEFINE_SYNC_REQUEST_R(__ssam_tmp_get_available_sensors, __le16, {
	.target_category = SSAM_SSH_TC_TMP,
	.target_id       = 0x01,
	.command_id      = 0x04,
	.instance_id     = 0x00,
});

static int ssam_tmp_get_available_sensors(struct ssam_device *sdev, u16 *sensors)
{
	__le16 sensors_le;
	int status;

	status = __ssam_tmp_get_available_sensors(sdev->ctrl, &sensors_le);
	if (status)
		return status;

	*sensors = le16_to_cpu(sensors_le);
	return 0;
}

static int ssam_add_thermal_sensor(struct ssam_device *sdev, u8 instance_id)
{
	struct ssam_device *sensor;
	int status;

	struct ssam_device_uid uid = {
		.domain = SSAM_DOMAIN_SERIALHUB,
		.category = SSAM_SSH_TC_TMP,
		.target = sdev->uid.target,
		.instance = instance_id,
		.function = 0x00,
	};

	sensor = ssam_device_alloc(sdev->ctrl, uid);
	if (!sdev)
		return -ENOMEM;

	sensor->dev.parent = &sdev->dev;

	status = ssam_device_add(sensor);
	if (status)
		ssam_device_put(sensor);

	return status;
}

static int ssam_thermal_hub_probe(struct ssam_device *sdev)
{
	u16 sensors;
	int status, i;

	/* Get bit-set specifying the available sensors instance IDs. */
	status = ssam_tmp_get_available_sensors(sdev, &sensors);
	if (status)
		return status;

	/* Instantiate the actual sensor devices. */
	for (i = 0; i < SSAM_TMP_MAX_SENSORS; i++) {
		if (sensors & BIT(i)) {
			status = ssam_add_thermal_sensor(sdev, i + 1);
			if (status)
				goto err;
		}
	}

	return 0;

err:
	ssam_remove_clients(&sdev->dev);
	return status;
}

static void ssam_thermal_hub_remove(struct ssam_device *sdev)
{
	ssam_remove_clients(&sdev->dev);
}

static const struct ssam_device_id ssam_thermal_hub_match[] = {
	{ SSAM_SDEV(TMP, 0x01, 0x00, 0x00) },
	{ },
};
MODULE_DEVICE_TABLE(ssam, ssam_thermal_hub_match);

static struct ssam_device_driver ssam_thermal_hub = {
	.probe = ssam_thermal_hub_probe,
	.remove = ssam_thermal_hub_remove,
	.match_table = ssam_thermal_hub_match,
	.driver = {
		.name = "surface_thermal_hub",
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};
module_ssam_device_driver(ssam_thermal_hub);

MODULE_AUTHOR("Maximilian Luz <luzmaximilian@gmail.com>");
MODULE_DESCRIPTION("Thermal sensor hub driver for Surface System Aggregator Module");
MODULE_LICENSE("GPL");
