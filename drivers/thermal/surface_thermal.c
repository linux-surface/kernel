// SPDX-License-Identifier: GPL-2.0+
/*
 * Thermal sensor driver for Surface System Aggregator Module (SSAM).
 *
 * Copyright (C) 2022 Maximilian Luz <luzmaximilian@gmail.com>
 */

#include <asm/unaligned.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/thermal.h>
#include <linux/types.h>

#include <linux/surface_aggregator/controller.h>
#include <linux/surface_aggregator/device.h>


/* -- SAM interface. -------------------------------------------------------- */

SSAM_DEFINE_SYNC_REQUEST_R(__ssam_tmp_get_available_sensors, __le16, {
	.target_category = SSAM_SSH_TC_TMP,
	.target_id       = 0x01,
	.command_id      = 0x04,
	.instance_id     = 0x00,
});

SSAM_DEFINE_SYNC_REQUEST_CL_R(__ssam_tmp_get_temperature, __le16, {
	.target_category = SSAM_SSH_TC_TMP,
	.command_id      = 0x01,
});

static int ssam_tmp_get_available_sensors(struct ssam_device *sdev, s16 *sensors)
{
	__le16 sensors_le;
	int status;

	status = __ssam_tmp_get_available_sensors(sdev->ctrl, &sensors_le);
	if (status)
		return status;

	*sensors = le16_to_cpu(sensors_le);
	return 0;
}

static int ssam_tmp_get_temperature(struct ssam_device *sdev, s16 *temperature)
{
	__le16 temp_le;
	int status;

	status = __ssam_tmp_get_temperature(sdev, &temp_le);
	if (status)
		return status;

	*temperature = le16_to_cpu(temp_le);
	return 0;
}


/* -- Driver.---------------------------------------------------------------- */

struct ssam_sensor {
	struct ssam_device *sdev;
	struct thermal_zone_device *tzd;
};

static inline int tmp_ssam_to_linux(s16 temperature)
{
	/* Convert centidegree to millidegree. */
	return temperature * 10;
}

static int ssam_thermal_get_temp(struct thermal_zone_device* tzd, int *temp)
{
	struct ssam_sensor *sensor = tzd->devdata;
	s16 temp_16;
	int status;

	status = ssam_tmp_get_temperature(sensor->sdev, &temp_16);
	if (status)
		return status;

	*temp = tmp_ssam_to_linux(temp_16);
	return 0;
}

static struct thermal_zone_device_ops ssam_thermal_ops = {
	.get_temp = ssam_thermal_get_temp,
};

static int ssam_thermal_sensor_probe(struct ssam_device *sdev)
{
	struct thermal_zone_device *tzd;
	struct ssam_sensor *sensor;
	u16 sensors;
	int status;

	/* Instance IDs must be 1 or larger. IID=0 is the hub device. */
	if (sdev->uid.instance < 1)
		return -ENODEV;

	/* Make sure that the sensor is actually present. */
	status = ssam_tmp_get_available_sensors(sdev, &sensors);
	if (status)
		return status;

	if (!(sensors & BIT(sdev->uid.instance - 1)))
		return -ENODEV;

	/* Set up driver data. */
	sensor = devm_kzalloc(&sdev->dev, sizeof(*sensor), GFP_KERNEL);
	if (!sensor)
		return -ENOMEM;

	sensor->sdev = sdev;

	/* Set up thermal zone device. */
	tzd = thermal_zone_device_register("ssam_thermal", 0, 0, sensor,
					   &ssam_thermal_ops, NULL, 0, 0);
	if (IS_ERR(tzd))
		return PTR_ERR(tzd);

	sensor->tzd = tzd;

	/* Enable thermal zone device. */
	status = thermal_zone_device_enable(sensor->tzd);
	if (status)
		goto err_enable;

	ssam_device_set_drvdata(sdev, sensor);
	return 0;

err_enable:
	thermal_zone_device_unregister(sensor->tzd);
	return status;
}

static void ssam_thermal_sensor_remove(struct ssam_device *sdev)
{
	struct ssam_sensor *sensor = ssam_device_get_drvdata(sdev);

	thermal_zone_device_unregister(sensor->tzd);
}

static const struct ssam_device_id ssam_thermal_sensor_match[] = {
	{ SSAM_SDEV(TMP, 0x01, SSAM_ANY_IID, 0x00) },
	{ },
};
MODULE_DEVICE_TABLE(ssam, ssam_thermal_sensor_match);

static struct ssam_device_driver ssam_thermal_sensor = {
	.probe = ssam_thermal_sensor_probe,
	.remove = ssam_thermal_sensor_remove,
	.match_table = ssam_thermal_sensor_match,
	.driver = {
		.name = "surface_thermal_sensor",
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};
module_ssam_device_driver(ssam_thermal_sensor);

MODULE_AUTHOR("Maximilian Luz <luzmaximilian@gmail.com>");
MODULE_DESCRIPTION("Thermal sensor driver for Surface System Aggregator Module");
MODULE_LICENSE("GPL");
