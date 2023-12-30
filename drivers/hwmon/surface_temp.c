// SPDX-License-Identifier: GPL-2.0+
/*
 * Thermal sensor subsystem driver for Surface System Aggregator Module (SSAM).
 *
 * Copyright (C) 2022-2023 Maximilian Luz <luzmaximilian@gmail.com>
 */

#include <linux/bitops.h>
#include <linux/hwmon.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>

#include <linux/surface_aggregator/controller.h>
#include <linux/surface_aggregator/device.h>


/* -- SAM interface. -------------------------------------------------------- */

SSAM_DEFINE_SYNC_REQUEST_CL_R(__ssam_tmp_get_available_sensors, __le16, {
	.target_category = SSAM_SSH_TC_TMP,
	.command_id      = 0x04,
});

SSAM_DEFINE_SYNC_REQUEST_MD_R(__ssam_tmp_get_temperature, __le16, {
	.target_category = SSAM_SSH_TC_TMP,
	.command_id      = 0x01,
});

static int ssam_tmp_get_available_sensors(struct ssam_device *sdev, s16 *sensors)
{
	__le16 sensors_le;
	int status;

	status = __ssam_tmp_get_available_sensors(sdev, &sensors_le);
	if (status)
		return status;

	*sensors = le16_to_cpu(sensors_le);
	return 0;
}

static int ssam_tmp_get_temperature(struct ssam_device *sdev, u8 iid, long *temperature)
{
	__le16 temp_le;
	int status;

	status = __ssam_tmp_get_temperature(sdev->ctrl, sdev->uid.target, iid, &temp_le);
	if (status)
		return status;

	/* Convert 1/10 °K to 1/1000 °C */
	*temperature = (le16_to_cpu(temp_le) - 2731) * 100L;
	return 0;
}


/* -- Driver.---------------------------------------------------------------- */

struct ssam_temp {
	struct ssam_device *sdev;
	s16 sensors;
};

static umode_t ssam_temp_hwmon_is_visible(const void *data,
					  enum hwmon_sensor_types type,
					  u32 attr, int channel)
{
	const struct ssam_temp *ssam_temp = data;

	if (!(ssam_temp->sensors & BIT(channel)))
		return 0;

	return 0444;
}

static int ssam_temp_hwmon_read(struct device *dev,
				enum hwmon_sensor_types type,
				u32 attr, int channel, long *value)
{
	const struct ssam_temp *ssam_temp = dev_get_drvdata(dev);

	return ssam_tmp_get_temperature(ssam_temp->sdev, channel + 1, value);
}

static const struct hwmon_channel_info * const ssam_temp_hwmon_info[] = {
	HWMON_CHANNEL_INFO(chip,
			   HWMON_C_REGISTER_TZ),
	/* We have at most 16 thermal sensor channels. */
	HWMON_CHANNEL_INFO(temp,
			   HWMON_T_INPUT,
			   HWMON_T_INPUT,
			   HWMON_T_INPUT,
			   HWMON_T_INPUT,
			   HWMON_T_INPUT,
			   HWMON_T_INPUT,
			   HWMON_T_INPUT,
			   HWMON_T_INPUT,
			   HWMON_T_INPUT,
			   HWMON_T_INPUT,
			   HWMON_T_INPUT,
			   HWMON_T_INPUT,
			   HWMON_T_INPUT,
			   HWMON_T_INPUT,
			   HWMON_T_INPUT,
			   HWMON_T_INPUT),
	NULL
};

static const struct hwmon_ops ssam_temp_hwmon_ops = {
	.is_visible = ssam_temp_hwmon_is_visible,
	.read = ssam_temp_hwmon_read,
};

static const struct hwmon_chip_info ssam_temp_hwmon_chip_info = {
	.ops = &ssam_temp_hwmon_ops,
	.info = ssam_temp_hwmon_info,
};

static int ssam_temp_probe(struct ssam_device *sdev)
{
	struct ssam_temp *ssam_temp;
	struct device *hwmon_dev;
	s16 sensors;
	int status;

	status = ssam_tmp_get_available_sensors(sdev, &sensors);
	if (status)
		return status;

	ssam_temp = devm_kzalloc(&sdev->dev, sizeof(*ssam_temp), GFP_KERNEL);
	if (!ssam_temp)
		return -ENOMEM;

	ssam_temp->sdev = sdev;
	ssam_temp->sensors = sensors;

	hwmon_dev = devm_hwmon_device_register_with_info(&sdev->dev,
			"surface_thermal", ssam_temp, &ssam_temp_hwmon_chip_info,
			NULL);
	if (IS_ERR(hwmon_dev))
		return PTR_ERR(hwmon_dev);

	return 0;
}

static const struct ssam_device_id ssam_temp_match[] = {
	{ SSAM_SDEV(TMP, SAM, 0x00, 0x02) },
	{ },
};
MODULE_DEVICE_TABLE(ssam, ssam_temp_match);

static struct ssam_device_driver ssam_temp = {
	.probe = ssam_temp_probe,
	.match_table = ssam_temp_match,
	.driver = {
		.name = "surface_temp",
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};
module_ssam_device_driver(ssam_temp);

MODULE_AUTHOR("Maximilian Luz <luzmaximilian@gmail.com>");
MODULE_DESCRIPTION("Thermal sensor subsystem driver for Surface System Aggregator Module");
MODULE_LICENSE("GPL");
