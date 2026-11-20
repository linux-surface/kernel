// SPDX-License-Identifier: GPL-2.0+
/*
 * Thermal sensor subsystem driver for Surface System Aggregator Module (SSAM).
 *
 * Copyright (C) 2022-2023 Maximilian Luz <luzmaximilian@gmail.com>
 */

#include <linux/bitops.h>
#include <linux/hwmon.h>
#include <linux/kernel.h>
#include <linux/math.h>
#include <linux/minmax.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/types.h>

#include <linux/surface_aggregator/controller.h>
#include <linux/surface_aggregator/device.h>

/* -- SAM interface. -------------------------------------------------------- */

/*
 * Available sensors are indicated by a 16-bit bitfield, where a 1 marks the
 * presence of a sensor. So we have at most 16 possible sensors/channels.
 */
#define SSAM_TMP_SENSOR_MAX_COUNT	16

/*
 * All names observed so far are 6 characters long, but there's only
 * zeros after the name, so perhaps they can be longer. This number reflects
 * the maximum zero-padded space observed in the returned buffer.
 */
#define SSAM_TMP_SENSOR_NAME_LENGTH	18

struct ssam_tmp_get_name_rsp {
	__le16 unknown1;
	char unknown2;
	char name[SSAM_TMP_SENSOR_NAME_LENGTH];
} __packed;

static_assert(sizeof(struct ssam_tmp_get_name_rsp) == 21);

/*
 * Command 0x24 takes the 1-based sensor index in the payload rather than
 * in the SSAM instance ID header field, followed by an IEEE 754 float
 * offset in degrees Celsius.
 */
struct ssam_tmp_set_offset_req {
	__u8 iid;
	__le32 offset_f32;
} __packed;

static_assert(sizeof(struct ssam_tmp_set_offset_req) == 5);

SSAM_DEFINE_SYNC_REQUEST_CL_R(__ssam_tmp_get_available_sensors, __le16, {
	.target_category = SSAM_SSH_TC_TMP,
	.command_id      = 0x04,
});

SSAM_DEFINE_SYNC_REQUEST_MD_R(__ssam_tmp_get_temperature, __le16, {
	.target_category = SSAM_SSH_TC_TMP,
	.command_id      = 0x01,
});

SSAM_DEFINE_SYNC_REQUEST_MD_R(__ssam_tmp_get_name, struct ssam_tmp_get_name_rsp, {
	.target_category = SSAM_SSH_TC_TMP,
	.command_id      = 0x0e,
});

SSAM_DEFINE_SYNC_REQUEST_CL_W(__ssam_tmp_set_offset, struct ssam_tmp_set_offset_req, {
	.target_category = SSAM_SSH_TC_TMP,
	.command_id      = 0x24,
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

static int ssam_tmp_get_name(struct ssam_device *sdev, u8 iid, char *buf, size_t buf_len)
{
	struct ssam_tmp_get_name_rsp name_rsp;
	int status;

	status =  __ssam_tmp_get_name(sdev->ctrl, sdev->uid.target, iid, &name_rsp);
	if (status)
		return status;

	/*
	 * This should not fail unless the name in the returned struct is not
	 * null-terminated or someone changed something in the struct
	 * definitions above, since our buffer and struct have the same
	 * capacity by design. So if this fails, log an error message. Since
	 * the more likely cause is that the returned string isn't
	 * null-terminated, we might have received garbage (as opposed to just
	 * an incomplete string), so also fail the function.
	 */
	status = strscpy(buf, name_rsp.name, buf_len);
	if (status < 0) {
		dev_err(&sdev->dev, "received non-null-terminated sensor name string\n");
		return status;
	}

	return 0;
}

static u32 ssam_tmp_mc_to_f32(long mc)
{
	u32 sign = 0;
	u64 scaled;
	u32 mant;
	int shift;
	int msb;

	if (mc == 0)
		return 0;

	if (mc < 0) {
		sign = BIT(31);
		mc = -mc;
	}

	scaled = DIV_ROUND_CLOSEST_ULL((u64)mc << 34, 1000);
	msb = fls64(scaled) - 1;
	shift = msb - 23;
	mant = (scaled + BIT_ULL(shift - 1)) >> shift;
	if (mant >= BIT(24)) {
		mant >>= 1;
		msb++;
	}

	return sign | ((127 + msb - 34) << 23) | (mant & GENMASK(22, 0));
}

static int ssam_tmp_set_offset(struct ssam_device *sdev, u8 iid, long offset_mc)
{
	struct ssam_tmp_set_offset_req req = {
		.iid = iid,
		.offset_f32 = cpu_to_le32(ssam_tmp_mc_to_f32(offset_mc)),
	};

	return __ssam_tmp_set_offset(sdev, &req);
}

/* -- Driver.---------------------------------------------------------------- */

struct ssam_temp {
	struct ssam_device *sdev;
	s16 sensors;
	char names[SSAM_TMP_SENSOR_MAX_COUNT][SSAM_TMP_SENSOR_NAME_LENGTH];
	struct mutex lock; /* Guards offsets[] and EC offset updates. */
	long offsets[SSAM_TMP_SENSOR_MAX_COUNT];
};

static umode_t ssam_temp_hwmon_is_visible(const void *data,
					  enum hwmon_sensor_types type,
					  u32 attr, int channel)
{
	const struct ssam_temp *ssam_temp = data;

	if (!(ssam_temp->sensors & BIT(channel)))
		return 0;

	if (type == hwmon_temp && attr == hwmon_temp_offset)
		return 0644;

	return 0444;
}

static int ssam_temp_hwmon_read(struct device *dev,
				enum hwmon_sensor_types type,
				u32 attr, int channel, long *value)
{
	struct ssam_temp *ssam_temp = dev_get_drvdata(dev);

	switch (attr) {
	case hwmon_temp_input:
		return ssam_tmp_get_temperature(ssam_temp->sdev, channel + 1, value);
	case hwmon_temp_offset:
		mutex_lock(&ssam_temp->lock);
		*value = ssam_temp->offsets[channel];
		mutex_unlock(&ssam_temp->lock);
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}

static int ssam_temp_hwmon_write(struct device *dev,
				 enum hwmon_sensor_types type,
				 u32 attr, int channel, long value)
{
	struct ssam_temp *ssam_temp = dev_get_drvdata(dev);
	int status;

	if (type != hwmon_temp || attr != hwmon_temp_offset)
		return -EOPNOTSUPP;

	value = clamp_val(value, -100000L, 100000L);

	mutex_lock(&ssam_temp->lock);
	status = ssam_tmp_set_offset(ssam_temp->sdev, channel + 1, value);
	if (!status)
		ssam_temp->offsets[channel] = value;
	mutex_unlock(&ssam_temp->lock);

	return status;
}

static int ssam_temp_hwmon_read_string(struct device *dev,
				       enum hwmon_sensor_types type,
				       u32 attr, int channel, const char **str)
{
	const struct ssam_temp *ssam_temp = dev_get_drvdata(dev);

	*str = ssam_temp->names[channel];
	return 0;
}

static const struct hwmon_channel_info * const ssam_temp_hwmon_info[] = {
	HWMON_CHANNEL_INFO(chip,
			   HWMON_C_REGISTER_TZ),
	HWMON_CHANNEL_INFO(temp,
			   HWMON_T_INPUT | HWMON_T_LABEL | HWMON_T_OFFSET,
			   HWMON_T_INPUT | HWMON_T_LABEL | HWMON_T_OFFSET,
			   HWMON_T_INPUT | HWMON_T_LABEL | HWMON_T_OFFSET,
			   HWMON_T_INPUT | HWMON_T_LABEL | HWMON_T_OFFSET,
			   HWMON_T_INPUT | HWMON_T_LABEL | HWMON_T_OFFSET,
			   HWMON_T_INPUT | HWMON_T_LABEL | HWMON_T_OFFSET,
			   HWMON_T_INPUT | HWMON_T_LABEL | HWMON_T_OFFSET,
			   HWMON_T_INPUT | HWMON_T_LABEL | HWMON_T_OFFSET,
			   HWMON_T_INPUT | HWMON_T_LABEL | HWMON_T_OFFSET,
			   HWMON_T_INPUT | HWMON_T_LABEL | HWMON_T_OFFSET,
			   HWMON_T_INPUT | HWMON_T_LABEL | HWMON_T_OFFSET,
			   HWMON_T_INPUT | HWMON_T_LABEL | HWMON_T_OFFSET,
			   HWMON_T_INPUT | HWMON_T_LABEL | HWMON_T_OFFSET,
			   HWMON_T_INPUT | HWMON_T_LABEL | HWMON_T_OFFSET,
			   HWMON_T_INPUT | HWMON_T_LABEL | HWMON_T_OFFSET,
			   HWMON_T_INPUT | HWMON_T_LABEL | HWMON_T_OFFSET),
	NULL
};

static const struct hwmon_ops ssam_temp_hwmon_ops = {
	.is_visible = ssam_temp_hwmon_is_visible,
	.read = ssam_temp_hwmon_read,
	.write = ssam_temp_hwmon_write,
	.read_string = ssam_temp_hwmon_read_string,
};

static const struct hwmon_chip_info ssam_temp_hwmon_chip_info = {
	.ops = &ssam_temp_hwmon_ops,
	.info = ssam_temp_hwmon_info,
};

static void ssam_temp_reset_offsets(void *data)
{
	struct ssam_temp *ssam_temp = data;
	int channel;

	for (channel = 0; channel < SSAM_TMP_SENSOR_MAX_COUNT; channel++) {
		if ((ssam_temp->sensors & BIT(channel)) && ssam_temp->offsets[channel] != 0)
			ssam_tmp_set_offset(ssam_temp->sdev, channel + 1, 0);
	}
}

static int ssam_temp_probe(struct ssam_device *sdev)
{
	struct ssam_temp *ssam_temp;
	struct device *hwmon_dev;
	s16 sensors;
	int channel;
	int status;

	status = ssam_tmp_get_available_sensors(sdev, &sensors);
	if (status)
		return status;

	ssam_temp = devm_kzalloc(&sdev->dev, sizeof(*ssam_temp), GFP_KERNEL);
	if (!ssam_temp)
		return -ENOMEM;

	ssam_temp->sdev = sdev;
	ssam_temp->sensors = sensors;
	mutex_init(&ssam_temp->lock);

	/* Retrieve the name for each available sensor. */
	for (channel = 0; channel < SSAM_TMP_SENSOR_MAX_COUNT; channel++) {
		if (!(sensors & BIT(channel)))
			continue;

		status = ssam_tmp_get_name(sdev, channel + 1, ssam_temp->names[channel],
					   SSAM_TMP_SENSOR_NAME_LENGTH);
		if (status)
			return status;
	}

	status = devm_add_action_or_reset(&sdev->dev, ssam_temp_reset_offsets, ssam_temp);
	if (status)
		return status;

	hwmon_dev = devm_hwmon_device_register_with_info(&sdev->dev, "surface_thermal", ssam_temp,
							 &ssam_temp_hwmon_chip_info, NULL);
	return PTR_ERR_OR_ZERO(hwmon_dev);
}

static const struct ssam_device_id ssam_temp_match[] = {
	{ SSAM_SDEV(TMP, SAM, 0x00, 0x02) },
	{ SSAM_SDEV(TMP, KIP, 0x00, 0x02) },
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
