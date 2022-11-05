// SPDX-License-Identifier: GPL-2.0+
/*
 * AC driver for 7th-generation Microsoft Surface devices via Surface System
 * Aggregator Module (SSAM).
 *
 * Copyright (C) 2019-2021 Maximilian Luz <luzmaximilian@gmail.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/rtc.h>
#include <linux/slab.h>
#include <linux/types.h>

#include <linux/surface_aggregator/device.h>

struct surface_rtc {
	struct ssam_device *sdev;
	struct rtc_device *rtc;
};

SSAM_DEFINE_SYNC_REQUEST_R(__ssam_rtc_get_unix_time, __le32, {
	.target_category = SSAM_SSH_TC_SAM,
	.target_id       = SSAM_SSH_TID_SAM,
	.instance_id     = 0x00,
	.command_id      = 0x10,
});

SSAM_DEFINE_SYNC_REQUEST_W(__ssam_rtc_set_unix_time, __le32, {
	.target_category = SSAM_SSH_TC_SAM,
	.target_id       = SSAM_SSH_TID_SAM,
	.instance_id     = 0x00,
	.command_id      = 0x0f,
});

static int ssam_rtc_get_unix_time(struct surface_rtc *srtc, u32 *time)
{
	__le32 time_le;
	int status;

	status = __ssam_rtc_get_unix_time(srtc->sdev->ctrl, &time_le);
	if (status)
		return status;

	*time = le32_to_cpu(time_le);
	return 0;
}

static int ssam_rtc_set_unix_time(struct surface_rtc *srtc, u32 time)
{
	__le32 time_le = cpu_to_le32(time);

	return __ssam_rtc_set_unix_time(srtc->sdev->ctrl, &time_le);
}

static int surface_rtc_read_time(struct device *dev, struct rtc_time *tm)
{
	struct surface_rtc *srtc = dev_get_drvdata(dev);
	int status;
	u32 time;

	status = ssam_rtc_get_unix_time(srtc, &time);
	if (status)
		return status;

	rtc_time64_to_tm(time, tm);
	return 0;
}

static int surface_rtc_set_time(struct device *dev, struct rtc_time *tm)
{
	struct surface_rtc *srtc = dev_get_drvdata(dev);
	time64_t time = rtc_tm_to_time64(tm);

	return ssam_rtc_set_unix_time(srtc, (u32)time);
}

static const struct rtc_class_ops surface_rtc_ops = {
	.read_time = surface_rtc_read_time,
	.set_time = surface_rtc_set_time,
};

static int surface_rtc_probe(struct ssam_device *sdev)
{
	struct surface_rtc *srtc;

	srtc = devm_kzalloc(&sdev->dev, sizeof(*srtc), GFP_KERNEL);
	if (!srtc)
		return -ENOMEM;

	srtc->sdev = sdev;

	srtc->rtc = devm_rtc_allocate_device(&sdev->dev);
	if (IS_ERR(srtc->rtc))
		return PTR_ERR(srtc->rtc);

	srtc->rtc->ops = &surface_rtc_ops;
	srtc->rtc->range_max = U32_MAX;

	ssam_device_set_drvdata(sdev, srtc);

	return devm_rtc_register_device(srtc->rtc);
}

static void surface_rtc_remove(struct ssam_device *sdev)
{
	/* Device-managed allocations take care of everything... */
}

static const struct ssam_device_id surface_rtc_match[] = {
	{ SSAM_SDEV(SAM, SAM, 0x00, 0x00) },
	{ },
};
MODULE_DEVICE_TABLE(ssam, surface_rtc_match);

static struct ssam_device_driver surface_rtc_driver = {
	.probe = surface_rtc_probe,
	.remove = surface_rtc_remove,
	.match_table = surface_rtc_match,
	.driver = {
		.name = "surface_rtc",
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};
module_ssam_device_driver(surface_rtc_driver);

MODULE_AUTHOR("Maximilian Luz <luzmaximilian@gmail.com>");
MODULE_DESCRIPTION("RTC driver for Surface System Aggregator Module");
MODULE_LICENSE("GPL");
