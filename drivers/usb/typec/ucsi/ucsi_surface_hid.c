// SPDX-License-Identifier: GPL-2.0
/*
 * UCSI-over-HID transport driver for Microsoft Surface devices.
 *
 * Exposes standard USB Type-C Connector System Software Interface (UCSI v1.x)
 * over the Surface System Aggregator Module (SSAM) HID transport for devices
 * advertising the Microsoft vendor UCSI PPM application collection
 * (HID\VID_045E&UP:FF00_U:F900), such as Surface Book 3 and Surface Pro X.
 *
 * Clean-room implementation based on HID report descriptor inspection and
 * live hardware verification on Surface Book 3.
 *
 * Copyright (C) 2026 Jairo Valdivia <valdiviaprado.ing@gmail.com>
 */

#include <linux/build_bug.h>
#include <linux/hid.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/workqueue.h>

#include "ucsi.h"

#define USB_VENDOR_ID_MICROSOFT			0x045e

#define SURFACE_UCSI_REPORT_ID_DATA		0x32
#define SURFACE_UCSI_REPORT_ID_CAPS		0x33
#define SURFACE_UCSI_MSG_SIZE			16

struct surface_ucsi_hid_data_report {
	u8 report_id;
	__le16 version;
	__le16 seq;
	__le32 cci;
	__le64 control;
	u8 message_in[SURFACE_UCSI_MSG_SIZE];
	u8 message_out[SURFACE_UCSI_MSG_SIZE];
} __packed;
static_assert(sizeof(struct surface_ucsi_hid_data_report) == 49);

struct surface_ucsi_hid_caps_report {
	u8 report_id;
	u8 num_connectors;
	u8 udc_supported;
} __packed;
static_assert(sizeof(struct surface_ucsi_hid_caps_report) == 3);

struct surface_ucsi_hid {
	struct hid_device *hdev;
	struct ucsi *ucsi;
	struct work_struct notify_work;

	struct mutex io_lock; /* Serializes HID raw feature requests and cache */
	struct surface_ucsi_hid_data_report *io_buf;
	struct surface_ucsi_hid_data_report rx_cache;
	bool cache_valid;

	u8 msg_out[SURFACE_UCSI_MSG_SIZE];
	size_t msg_out_len;
};

static int surface_ucsi_hid_fetch_report(struct surface_ucsi_hid *ush, u32 *cci)
{
	int ret;

	mutex_lock(&ush->io_lock);

	memset(ush->io_buf, 0, sizeof(*ush->io_buf));
	ush->io_buf->report_id = SURFACE_UCSI_REPORT_ID_DATA;

	ret = hid_hw_raw_request(ush->hdev, SURFACE_UCSI_REPORT_ID_DATA,
				 (u8 *)ush->io_buf, sizeof(*ush->io_buf),
				 HID_FEATURE_REPORT, HID_REQ_GET_REPORT);
	if (ret < 0)
		goto out_unlock;
	if (ret < (int)sizeof(*ush->io_buf)) {
		ret = -EPROTO;
		goto out_unlock;
	}

	ush->rx_cache = *ush->io_buf;
	ush->cache_valid = true;
	if (cci)
		*cci = le32_to_cpu(ush->rx_cache.cci);
	ret = 0;

out_unlock:
	mutex_unlock(&ush->io_lock);
	return ret;
}

static int surface_ucsi_hid_read_version(struct ucsi *ucsi, u16 *version)
{
	struct surface_ucsi_hid *ush = ucsi_get_drvdata(ucsi);
	u16 ver;
	int ret;

	ret = surface_ucsi_hid_fetch_report(ush, NULL);
	if (ret)
		return ret;

	mutex_lock(&ush->io_lock);
	ver = le16_to_cpu(ush->rx_cache.version);
	mutex_unlock(&ush->io_lock);

	/*
	 * Prior to UCSI_PPM_RESET, the SAM HID Feature Report 0x32 buffer may
	 * contain uninitialized bytes in the version field (e.g. 0x7628 on
	 * Surface Book 3). Because Report 0x32 carries fixed 16-byte
	 * MESSAGE_IN/MESSAGE_OUT buffers, this transport strictly implements
	 * UCSI v1.x. Fall back to UCSI v1.1 when the pre-reset value is not a
	 * valid UCSI v1.x BCD revision.
	 */
	if (ver != UCSI_VERSION_1_0 && ver != UCSI_VERSION_1_1 &&
	    ver != UCSI_VERSION_1_2) {
		hid_dbg(ush->hdev,
			"sanitizing pre-reset UCSI version 0x%04x to 0x%04x\n",
			ver, UCSI_VERSION_1_1);
		ver = UCSI_VERSION_1_1;
	}

	*version = ver;
	return 0;
}

static int surface_ucsi_hid_read_cci(struct ucsi *ucsi, u32 *cci)
{
	struct surface_ucsi_hid *ush = ucsi_get_drvdata(ucsi);
	bool valid;

	mutex_lock(&ush->io_lock);
	valid = ush->cache_valid;
	if (valid)
		*cci = le32_to_cpu(ush->rx_cache.cci);
	mutex_unlock(&ush->io_lock);

	if (!valid)
		return surface_ucsi_hid_fetch_report(ush, cci);

	return 0;
}

static int surface_ucsi_hid_poll_cci(struct ucsi *ucsi, u32 *cci)
{
	struct surface_ucsi_hid *ush = ucsi_get_drvdata(ucsi);

	return surface_ucsi_hid_fetch_report(ush, cci);
}

static int surface_ucsi_hid_read_message_in(struct ucsi *ucsi, void *val,
					    size_t val_len)
{
	struct surface_ucsi_hid *ush = ucsi_get_drvdata(ucsi);

	if (val_len > SURFACE_UCSI_MSG_SIZE)
		return -EINVAL;

	mutex_lock(&ush->io_lock);
	memcpy(val, ush->rx_cache.message_in, val_len);
	mutex_unlock(&ush->io_lock);

	return 0;
}

static int surface_ucsi_hid_write_message_out(struct ucsi *ucsi, void *data,
					      size_t data_len)
{
	struct surface_ucsi_hid *ush = ucsi_get_drvdata(ucsi);

	if (!data || !data_len || data_len > SURFACE_UCSI_MSG_SIZE)
		return -EINVAL;

	mutex_lock(&ush->io_lock);
	memset(ush->msg_out, 0, sizeof(ush->msg_out));
	memcpy(ush->msg_out, data, data_len);
	ush->msg_out_len = data_len;
	mutex_unlock(&ush->io_lock);

	return 0;
}

static int surface_ucsi_hid_async_control(struct ucsi *ucsi, u64 command)
{
	struct surface_ucsi_hid *ush = ucsi_get_drvdata(ucsi);
	int ret;

	mutex_lock(&ush->io_lock);

	memset(ush->io_buf, 0, sizeof(*ush->io_buf));
	ush->io_buf->report_id = SURFACE_UCSI_REPORT_ID_DATA;
	ush->io_buf->seq = cpu_to_le16(0);
	ush->io_buf->control = cpu_to_le64(command);

	if (ush->msg_out_len) {
		memcpy(ush->io_buf->message_out, ush->msg_out, ush->msg_out_len);
		ush->msg_out_len = 0;
	}

	ret = hid_hw_raw_request(ush->hdev, SURFACE_UCSI_REPORT_ID_DATA,
				 (u8 *)ush->io_buf, sizeof(*ush->io_buf),
				 HID_FEATURE_REPORT, HID_REQ_SET_REPORT);

	mutex_unlock(&ush->io_lock);

	return ret < 0 ? ret : 0;
}

static const struct ucsi_operations surface_ucsi_hid_ops = {
	.read_version = surface_ucsi_hid_read_version,
	.read_cci = surface_ucsi_hid_read_cci,
	.poll_cci = surface_ucsi_hid_poll_cci,
	.read_message_in = surface_ucsi_hid_read_message_in,
	.write_message_out = surface_ucsi_hid_write_message_out,
	.sync_control = ucsi_sync_control_common,
	.async_control = surface_ucsi_hid_async_control,
};

static void surface_ucsi_hid_notify_work(struct work_struct *work)
{
	struct surface_ucsi_hid *ush =
		container_of(work, struct surface_ucsi_hid, notify_work);
	u32 cci;
	int ret;

	ret = surface_ucsi_hid_fetch_report(ush, &cci);
	if (ret) {
		hid_warn(ush->hdev, "failed to read UCSI feature report: %d\n",
			 ret);
		return;
	}

	ucsi_notify_common(ush->ucsi, cci);
}

static int surface_ucsi_hid_raw_event(struct hid_device *hdev,
				      struct hid_report *report,
				      u8 *data, int size)
{
	struct surface_ucsi_hid *ush = hid_get_drvdata(hdev);

	if (!ush)
		return 0;

	if (size < 1 || data[0] != SURFACE_UCSI_REPORT_ID_DATA)
		return 0;

	schedule_work(&ush->notify_work);
	return 1;
}

static void surface_ucsi_hid_log_caps(struct surface_ucsi_hid *ush)
{
	struct surface_ucsi_hid_caps_report *caps =
		(struct surface_ucsi_hid_caps_report *)ush->io_buf;
	int ret;

	if (!ush->hdev->report_enum[HID_FEATURE_REPORT].report_id_hash[SURFACE_UCSI_REPORT_ID_CAPS])
		return;

	memset(caps, 0, sizeof(*caps));
	caps->report_id = SURFACE_UCSI_REPORT_ID_CAPS;
	ret = hid_hw_raw_request(ush->hdev, SURFACE_UCSI_REPORT_ID_CAPS,
				 (u8 *)caps, sizeof(*caps),
				 HID_FEATURE_REPORT, HID_REQ_GET_REPORT);
	if (ret == sizeof(*caps))
		hid_info(ush->hdev,
			 "Surface UCSI HID PPM (connectors=%u, udc_supported=%u)\n",
			 caps->num_connectors, caps->udc_supported);
}

static int surface_ucsi_hid_probe(struct hid_device *hdev,
				  const struct hid_device_id *id)
{
	struct surface_ucsi_hid *ush;
	int ret;

	ret = hid_parse(hdev);
	if (ret)
		return dev_err_probe(&hdev->dev, ret, "HID parse failed\n");

	if (!hdev->report_enum[HID_FEATURE_REPORT].report_id_hash[SURFACE_UCSI_REPORT_ID_DATA])
		return -ENODEV;

	ush = devm_kzalloc(&hdev->dev, sizeof(*ush), GFP_KERNEL);
	if (!ush)
		return -ENOMEM;

	ush->io_buf = devm_kzalloc(&hdev->dev, sizeof(*ush->io_buf), GFP_KERNEL);
	if (!ush->io_buf)
		return -ENOMEM;

	ush->hdev = hdev;
	mutex_init(&ush->io_lock);
	INIT_WORK(&ush->notify_work, surface_ucsi_hid_notify_work);
	hid_set_drvdata(hdev, ush);

	ret = hid_hw_start(hdev, HID_CONNECT_HIDRAW);
	if (ret)
		return dev_err_probe(&hdev->dev, ret, "HID hw_start failed\n");

	ret = hid_hw_open(hdev);
	if (ret) {
		dev_err_probe(&hdev->dev, ret, "HID hw_open failed\n");
		goto err_hw_stop;
	}

	surface_ucsi_hid_log_caps(ush);

	ush->ucsi = ucsi_create(&hdev->dev, &surface_ucsi_hid_ops);
	if (IS_ERR(ush->ucsi)) {
		ret = dev_err_probe(&hdev->dev, PTR_ERR(ush->ucsi),
				    "ucsi_create failed\n");
		goto err_hw_close;
	}

	ucsi_set_drvdata(ush->ucsi, ush);
	hid_device_io_start(hdev);

	ret = ucsi_register(ush->ucsi);
	if (ret) {
		dev_err_probe(&hdev->dev, ret, "ucsi_register failed\n");
		goto err_io_stop;
	}

	return 0;

err_io_stop:
	hid_device_io_stop(hdev);
	cancel_work_sync(&ush->notify_work);
	ucsi_destroy(ush->ucsi);
err_hw_close:
	hid_hw_close(hdev);
err_hw_stop:
	hid_hw_stop(hdev);
	hid_set_drvdata(hdev, NULL);
	return ret;
}

static void surface_ucsi_hid_remove(struct hid_device *hdev)
{
	struct surface_ucsi_hid *ush = hid_get_drvdata(hdev);

	ucsi_unregister(ush->ucsi);
	hid_device_io_stop(hdev);
	cancel_work_sync(&ush->notify_work);
	ucsi_destroy(ush->ucsi);

	hid_hw_close(hdev);
	hid_hw_stop(hdev);
	hid_set_drvdata(hdev, NULL);
}

#ifdef CONFIG_PM
static int surface_ucsi_hid_suspend(struct hid_device *hdev,
				    pm_message_t message)
{
	struct surface_ucsi_hid *ush = hid_get_drvdata(hdev);
	int ret;

	ret = ucsi_suspend(ush->ucsi);
	cancel_work_sync(&ush->notify_work);
	return ret;
}

static int surface_ucsi_hid_resume(struct hid_device *hdev)
{
	struct surface_ucsi_hid *ush = hid_get_drvdata(hdev);

	return ucsi_resume(ush->ucsi);
}

static int surface_ucsi_hid_reset_resume(struct hid_device *hdev)
{
	struct surface_ucsi_hid *ush = hid_get_drvdata(hdev);

	return ucsi_resume(ush->ucsi);
}
#endif

static const struct hid_device_id surface_ucsi_hid_table[] = {
	{ HID_DEVICE(HID_BUS_ANY, HID_GROUP_SURFACE_UCSI,
		     USB_VENDOR_ID_MICROSOFT, HID_ANY_ID) },
	{ }
};
MODULE_DEVICE_TABLE(hid, surface_ucsi_hid_table);

static struct hid_driver surface_ucsi_hid_driver = {
	.name = "ucsi_surface_hid",
	.id_table = surface_ucsi_hid_table,
	.probe = surface_ucsi_hid_probe,
	.remove = surface_ucsi_hid_remove,
	.raw_event = surface_ucsi_hid_raw_event,
#ifdef CONFIG_PM
	.suspend = surface_ucsi_hid_suspend,
	.resume = surface_ucsi_hid_resume,
	.reset_resume = surface_ucsi_hid_reset_resume,
#endif
};
module_hid_driver(surface_ucsi_hid_driver);

MODULE_AUTHOR("Jairo Valdivia <valdiviaprado.ing@gmail.com>");
MODULE_DESCRIPTION("Microsoft Surface UCSI-over-HID transport driver");
MODULE_LICENSE("GPL");
