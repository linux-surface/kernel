// SPDX-License-Identifier: GPL-2.0+
/*
 * Surface System Aggregator Module (SSAM) HID device driver.
 *
 * Provides support for HID input devices connected via the Surface System
 * Aggregator Module.
 *
 * Copyright (C) 2019-2020 Blaž Hrastnik <blaz@mxxn.io>,
 *                         Maximilian Luz <luzmaximilian@gmail.com>
 */

#include <asm/unaligned.h>
#include <linux/hid.h>
#include <linux/input.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/usb/ch9.h>

#include <linux/surface_aggregator/controller.h>
#include <linux/surface_aggregator/device.h>

#define SHID_RETRY			3
#define shid_retry(fn, args...)		ssam_retry(fn, SHID_RETRY, args)


enum surface_hid_descriptor_entry {
	SURFACE_HID_DESC_HID    = 0,
	SURFACE_HID_DESC_REPORT = 1,
	SURFACE_HID_DESC_ATTRS  = 2,
};

struct surface_hid_descriptor {
	__u8 desc_len;			// = 9
	__u8 desc_type;			// = HID_DT_HID
	__le16 hid_version;
	__u8 country_code;
	__u8 num_descriptors;		// = 1

	__u8 report_desc_type;		// = HID_DT_REPORT
	__le16 report_desc_len;
} __packed;

static_assert(sizeof(struct surface_hid_descriptor) == 9);

struct surface_hid_attributes {
	__le32 length;
	__le16 vendor;
	__le16 product;
	__le16 version;
	__u8 _unknown[22];
} __packed;

static_assert(sizeof(struct surface_hid_attributes) == 32);

struct surface_hid_buffer_slice {
	__u8 entry;
	__le32 offset;
	__le32 length;
	__u8 end;
	__u8 data[];
} __packed;

static_assert(sizeof(struct surface_hid_buffer_slice) == 10);

enum surface_hid_cid {
	SURFACE_HID_CID_OUTPUT_REPORT      = 0x01,
	SURFACE_HID_CID_GET_FEATURE_REPORT = 0x02,
	SURFACE_HID_CID_SET_FEATURE_REPORT = 0x03,
	SURFACE_HID_CID_GET_DESCRIPTOR     = 0x04,
};

struct surface_hid_device {
	struct device *dev;
	struct ssam_controller *ctrl;
	struct ssam_device_uid uid;

	struct surface_hid_descriptor hid_desc;
	struct surface_hid_attributes attrs;

	struct ssam_event_notifier notif;
	struct hid_device *hid;
};


/* -- SAM interface. -------------------------------------------------------- */

static int ssam_hid_get_descriptor(struct surface_hid_device *shid, u8 entry,
				   u8 *buf, size_t len)
{
	u8 buffer[sizeof(struct surface_hid_buffer_slice) + 0x76];
	struct surface_hid_buffer_slice *slice;
	struct ssam_request rqst;
	struct ssam_response rsp;
	u32 buffer_len, offset, length;
	int status;

	/*
	 * Note: The 0x76 above has been chosen because that's what's used by
	 * the Windows driver. Together with the header, this leads to a 128
	 * byte payload in total.
	 */

	buffer_len = ARRAY_SIZE(buffer) - sizeof(struct surface_hid_buffer_slice);

	rqst.target_category = shid->uid.category;
	rqst.target_id = shid->uid.target;
	rqst.command_id = SURFACE_HID_CID_GET_DESCRIPTOR;
	rqst.instance_id = shid->uid.instance;
	rqst.flags = SSAM_REQUEST_HAS_RESPONSE;
	rqst.length = sizeof(struct surface_hid_buffer_slice);
	rqst.payload = buffer;

	rsp.capacity = ARRAY_SIZE(buffer);
	rsp.pointer = buffer;

	slice = (struct surface_hid_buffer_slice *)buffer;
	slice->entry = entry;
	slice->end = 0;

	offset = 0;
	length = buffer_len;

	while (!slice->end && offset < len) {
		put_unaligned_le32(offset, &slice->offset);
		put_unaligned_le32(length, &slice->length);

		rsp.length = 0;

		status = shid_retry(ssam_request_sync, shid->ctrl, &rqst, &rsp);
		if (status)
			return status;

		offset = get_unaligned_le32(&slice->offset);
		length = get_unaligned_le32(&slice->length);

		// don't mess stuff up in case we receive garbage
		if (length > buffer_len || offset > len)
			return -EPROTO;

		if (offset + length > len)
			length = len - offset;

		memcpy(buf + offset, &slice->data[0], length);

		offset += length;
		length = buffer_len;
	}

	if (offset != len) {
		dev_err(shid->dev, "unexpected descriptor length: got %u, "
			"expected %zu\n", offset, len);
		return -EPROTO;
	}

	return 0;
}

static int ssam_hid_set_raw_report(struct surface_hid_device *shid,
				   u8 report_id, bool feature, u8 *buf,
				   size_t len)
{
	struct ssam_request rqst;
	u8 cid;

	if (feature)
		cid = SURFACE_HID_CID_SET_FEATURE_REPORT;
	else
		cid = SURFACE_HID_CID_OUTPUT_REPORT;

	rqst.target_category = shid->uid.category;
	rqst.target_id = shid->uid.target;
	rqst.instance_id = shid->uid.instance;
	rqst.command_id = cid;
	rqst.flags = 0;
	rqst.length = len;
	rqst.payload = buf;

	buf[0] = report_id;

	return shid_retry(ssam_request_sync, shid->ctrl, &rqst, NULL);
}

static int ssam_hid_get_raw_report(struct surface_hid_device *shid,
				   u8 report_id, u8 *buf, size_t len)
{
	struct ssam_request rqst;
	struct ssam_response rsp;

	rqst.target_category = shid->uid.category;
	rqst.target_id = shid->uid.target;
	rqst.instance_id = shid->uid.instance;
	rqst.command_id = SURFACE_HID_CID_GET_FEATURE_REPORT;
	rqst.flags = 0;
	rqst.length = sizeof(u8);
	rqst.payload = &report_id;

	rsp.capacity = len;
	rsp.length = 0;
	rsp.pointer = buf;

	return shid_retry(ssam_request_sync, shid->ctrl, &rqst, &rsp);
}

static u32 ssam_hid_event_fn(struct ssam_event_notifier *nf,
			     const struct ssam_event *event)
{
	struct surface_hid_device *shid;
	int status;

	shid = container_of(nf, struct surface_hid_device, notif);

	if (event->command_id != 0x00)
		return 0;

	status = hid_input_report(shid->hid, HID_INPUT_REPORT,
				  (u8 *)&event->data[0], event->length, 0);

	return ssam_notifier_from_errno(status) | SSAM_NOTIF_HANDLED;
}


/* -- Device descriptor access. --------------------------------------------- */

static int surface_hid_load_hid_descriptor(struct surface_hid_device *shid)
{
	int status;

	status = ssam_hid_get_descriptor(shid, SURFACE_HID_DESC_HID,
			(u8 *)&shid->hid_desc, sizeof(shid->hid_desc));
	if (status)
		return status;

	if (shid->hid_desc.desc_len != sizeof(shid->hid_desc)) {
		dev_err(shid->dev, "unexpected HID descriptor length: got %u, "
			"expected %zu\n", shid->hid_desc.desc_len,
			sizeof(shid->hid_desc));
		return -EPROTO;
	}

	if (shid->hid_desc.desc_type != HID_DT_HID) {
		dev_err(shid->dev, "unexpected HID descriptor type: got 0x%x, "
			"expected 0x%x\n", shid->hid_desc.desc_type,
			HID_DT_HID);
		return -EPROTO;
	}

	if (shid->hid_desc.num_descriptors != 1) {
		dev_err(shid->dev, "unexpected number of descriptors: got %u, "
			"expected 1\n", shid->hid_desc.num_descriptors);
		return -EPROTO;
	}

	if (shid->hid_desc.report_desc_type != HID_DT_REPORT) {
		dev_err(shid->dev, "unexpected report descriptor type: got 0x%x, "
			"expected 0x%x\n", shid->hid_desc.report_desc_type,
			HID_DT_REPORT);
		return -EPROTO;
	}

	return 0;
}

static int surface_hid_load_device_attributes(struct surface_hid_device *shid)
{
	int status;

	status = ssam_hid_get_descriptor(shid, SURFACE_HID_DESC_ATTRS,
			(u8 *)&shid->attrs, sizeof(shid->attrs));
	if (status)
		return status;

	if (get_unaligned_le32(&shid->attrs.length) != sizeof(shid->attrs)) {
		dev_err(shid->dev, "unexpected attribute length: got %u, "
			"expected %zu\n", get_unaligned_le32(&shid->attrs.length),
			sizeof(shid->attrs));
		return -EPROTO;
	}

	return 0;
}


/* -- Transport driver. ----------------------------------------------------- */

static int shid_output_report(struct surface_hid_device *shid, u8 report_id,
			      u8 *data, size_t len)
{
	int status;

	status =  ssam_hid_set_raw_report(shid, report_id, false, data, len);
	return status >= 0 ? len : status;
}

static int shid_get_feature_report(struct surface_hid_device *shid,
				   u8 report_id, u8 *data, size_t len)
{
	int status;

	status = ssam_hid_get_raw_report(shid, report_id, data, len);
	return status >= 0 ? len : status;
}

static int shid_set_feature_report(struct surface_hid_device *shid,
				   u8 report_id, u8 *data, size_t len)
{
	int status;

	status =  ssam_hid_set_raw_report(shid, report_id, true, data, len);
	return status >= 0 ? len : status;
}


static int surface_hid_start(struct hid_device *hid)
{
	struct surface_hid_device *shid = hid->driver_data;

	return ssam_notifier_register(shid->ctrl, &shid->notif);
}

static void surface_hid_stop(struct hid_device *hid)
{
	struct surface_hid_device *shid = hid->driver_data;

	// Note: This call will log errors for us, so ignore them here.
	ssam_notifier_unregister(shid->ctrl, &shid->notif);
}

static int surface_hid_open(struct hid_device *hid)
{
	return 0;
}

static void surface_hid_close(struct hid_device *hid)
{
}

static int surface_hid_parse(struct hid_device *hid)
{
	struct surface_hid_device *shid = hid->driver_data;
	size_t len = get_unaligned_le16(&shid->hid_desc.report_desc_len);
	u8 *buf;
	int status;

	buf = kzalloc(len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	status = ssam_hid_get_descriptor(shid, SURFACE_HID_DESC_REPORT, buf, len);
	if (!status)
		status = hid_parse_report(hid, buf, len);

	kfree(buf);
	return status;
}

static int surface_hid_raw_request(struct hid_device *hid,
		unsigned char reportnum, u8 *buf, size_t len,
		unsigned char rtype, int reqtype)
{
	struct surface_hid_device *shid = hid->driver_data;

	if (rtype == HID_OUTPUT_REPORT && reqtype == HID_REQ_SET_REPORT)
		return shid_output_report(shid, reportnum, buf, len);

	else if (rtype == HID_FEATURE_REPORT && reqtype == HID_REQ_GET_REPORT)
		return shid_get_feature_report(shid, reportnum, buf, len);

	else if (rtype == HID_FEATURE_REPORT && reqtype == HID_REQ_SET_REPORT)
		return shid_set_feature_report(shid, reportnum, buf, len);

	return -EIO;
}

static struct hid_ll_driver surface_hid_ll_driver = {
	.start       = surface_hid_start,
	.stop        = surface_hid_stop,
	.open        = surface_hid_open,
	.close       = surface_hid_close,
	.parse       = surface_hid_parse,
	.raw_request = surface_hid_raw_request,
};


/* -- Common device setup. -------------------------------------------------- */

static int surface_hid_device_add(struct surface_hid_device *shid)
{
	int status;

	status = surface_hid_load_hid_descriptor(shid);
	if (status)
		return status;

	status = surface_hid_load_device_attributes(shid);
	if (status)
		return status;

	shid->hid = hid_allocate_device();
	if (IS_ERR(shid->hid))
		return PTR_ERR(shid->hid);

	shid->hid->dev.parent = shid->dev;
	shid->hid->bus = BUS_VIRTUAL;		// TODO: BUS_SURFACE
	shid->hid->vendor = cpu_to_le16(shid->attrs.vendor);
	shid->hid->product = cpu_to_le16(shid->attrs.product);
	shid->hid->version = cpu_to_le16(shid->hid_desc.hid_version);
	shid->hid->country = shid->hid_desc.country_code;

	snprintf(shid->hid->name, sizeof(shid->hid->name),
		 "Microsoft Surface %04X:%04X",
		 shid->hid->vendor, shid->hid->product);

	strlcpy(shid->hid->phys, dev_name(shid->dev), sizeof(shid->hid->phys));

	shid->hid->driver_data = shid;
	shid->hid->ll_driver = &surface_hid_ll_driver;

	status = hid_add_device(shid->hid);
	if (status)
		hid_destroy_device(shid->hid);

	return status;
}

static void surface_hid_device_destroy(struct surface_hid_device *shid)
{
	hid_destroy_device(shid->hid);
}


/* -- PM ops. --------------------------------------------------------------- */

#ifdef CONFIG_PM

static int surface_hid_suspend(struct device *dev)
{
	struct surface_hid_device *d = dev_get_drvdata(dev);

	if (d->hid->driver && d->hid->driver->suspend)
		return d->hid->driver->suspend(d->hid, PMSG_SUSPEND);

	return 0;
}

static int surface_hid_resume(struct device *dev)
{
	struct surface_hid_device *d = dev_get_drvdata(dev);

	if (d->hid->driver && d->hid->driver->resume)
		return d->hid->driver->resume(d->hid);

	return 0;
}

static int surface_hid_freeze(struct device *dev)
{
	struct surface_hid_device *d = dev_get_drvdata(dev);

	if (d->hid->driver && d->hid->driver->suspend)
		return d->hid->driver->suspend(d->hid, PMSG_FREEZE);

	return 0;
}

static int surface_hid_poweroff(struct device *dev)
{
	struct surface_hid_device *d = dev_get_drvdata(dev);

	if (d->hid->driver && d->hid->driver->suspend)
		return d->hid->driver->suspend(d->hid, PMSG_HIBERNATE);

	return 0;
}

static int surface_hid_restore(struct device *dev)
{
	struct surface_hid_device *d = dev_get_drvdata(dev);

	if (d->hid->driver && d->hid->driver->reset_resume)
		return d->hid->driver->reset_resume(d->hid);

	return 0;
}

const struct dev_pm_ops surface_hid_pm_ops = {
	.freeze   = surface_hid_freeze,
	.thaw     = surface_hid_resume,
	.suspend  = surface_hid_suspend,
	.resume   = surface_hid_resume,
	.poweroff = surface_hid_poweroff,
	.restore  = surface_hid_restore,
};

#else /* CONFIG_PM */

const struct dev_pm_ops surface_hid_pm_ops = { };

#endif /* CONFIG_PM */


/* -- Driver setup. --------------------------------------------------------- */

static int surface_hid_probe(struct ssam_device *sdev)
{
	struct surface_hid_device *shid;

	shid = devm_kzalloc(&sdev->dev, sizeof(*shid), GFP_KERNEL);
	if (!shid)
		return -ENOMEM;

	shid->dev = &sdev->dev;
	shid->ctrl = sdev->ctrl;
	shid->uid = sdev->uid;

	shid->notif.base.priority = 1;
	shid->notif.base.fn = ssam_hid_event_fn;
	shid->notif.event.reg = SSAM_EVENT_REGISTRY_REG,
	shid->notif.event.id.target_category = sdev->uid.category;
	shid->notif.event.id.instance = sdev->uid.instance;
	shid->notif.event.mask = SSAM_EVENT_MASK_STRICT;
	shid->notif.event.flags = 0;

	ssam_device_set_drvdata(sdev, shid);
	return surface_hid_device_add(shid);
}

static void surface_hid_remove(struct ssam_device *sdev)
{
	surface_hid_device_destroy(ssam_device_get_drvdata(sdev));
}

static const struct ssam_device_id surface_hid_match[] = {
	{ SSAM_SDEV(HID, 0x02, SSAM_ANY_IID, 0x00) },
	{ },
};
MODULE_DEVICE_TABLE(ssam, surface_hid_match);

static struct ssam_device_driver surface_hid_driver = {
	.probe = surface_hid_probe,
	.remove = surface_hid_remove,
	.match_table = surface_hid_match,
	.driver = {
		.name = "surface_hid",
		.pm = &surface_hid_pm_ops,
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};
module_ssam_device_driver(surface_hid_driver);

MODULE_AUTHOR("Blaž Hrastnik <blaz@mxxn.io>");
MODULE_AUTHOR("Maximilian Luz <luzmaximilian@gmail.com>");
MODULE_DESCRIPTION("HID transport-/device-driver for Surface System Aggregator Module");
MODULE_LICENSE("GPL");
