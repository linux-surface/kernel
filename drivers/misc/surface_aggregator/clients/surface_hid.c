// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Surface System Aggregator Module (SSAM) HID device driver.
 *
 * Provides support for HID input devices connected via the Surface System
 * Aggregator Module.
 */

#include <linux/hid.h>
#include <linux/input.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/types.h>

#include <linux/surface_aggregator/device.h>


#define SID_VHF_INPUT_NAME	"Microsoft Surface HID"

#define SAM_EVENT_SID_VHF_TC	0x15

#define VHF_HID_STARTED		0

struct sid_vhf_properties {
	struct ssam_event_registry registry;
};

struct sid_vhf {
	struct ssam_device *sdev;
	struct ssam_event_notifier notif;

	struct hid_device *hid;
	unsigned long state;
};


static int sid_vhf_hid_start(struct hid_device *hid)
{
	hid_dbg(hid, "%s\n", __func__);
	return 0;
}

static void sid_vhf_hid_stop(struct hid_device *hid)
{
	hid_dbg(hid, "%s\n", __func__);
}

static int sid_vhf_hid_open(struct hid_device *hid)
{
	struct sid_vhf *vhf = dev_get_drvdata(hid->dev.parent);

	hid_dbg(hid, "%s\n", __func__);

	set_bit(VHF_HID_STARTED, &vhf->state);
	return 0;
}

static void sid_vhf_hid_close(struct hid_device *hid)
{

	struct sid_vhf *vhf = dev_get_drvdata(hid->dev.parent);

	hid_dbg(hid, "%s\n", __func__);

	clear_bit(VHF_HID_STARTED, &vhf->state);
}

struct surface_sam_sid_vhf_meta_rqst {
	u8 id;
	u32 offset;
	u32 length; // buffer limit on send, length of data received on receive
	u8 end; // 0x01 if end was reached
} __packed;

struct vhf_device_metadata_info {
	u8 len;
	u8 _2;
	u8 _3;
	u8 _4;
	u8 _5;
	u8 _6;
	u8 _7;
	u16 hid_len; // hid descriptor length
} __packed;

struct vhf_device_metadata {
	u32 len;
	u16 vendor_id;
	u16 product_id;
	u8  _1[24];
} __packed;

union vhf_buffer_data {
	struct vhf_device_metadata_info info;
	u8 pld[0x76];
	struct vhf_device_metadata meta;
};

struct surface_sam_sid_vhf_meta_resp {
	struct surface_sam_sid_vhf_meta_rqst rqst;
	union vhf_buffer_data data;
} __packed;


static int vhf_get_metadata(struct ssam_device *sdev, struct vhf_device_metadata *meta)
{
	struct surface_sam_sid_vhf_meta_resp data = {};
	struct ssam_request rqst;
	struct ssam_response rsp;
	int status;

	data.rqst.id = 2;
	data.rqst.offset = 0;
	data.rqst.length = 0x76;
	data.rqst.end = 0;

	rqst.target_category = sdev->uid.category;
	rqst.target_id = sdev->uid.target;
	rqst.command_id = 0x04;
	rqst.instance_id = sdev->uid.instance;
	rqst.flags = SSAM_REQUEST_HAS_RESPONSE;
	rqst.length = sizeof(struct surface_sam_sid_vhf_meta_rqst);
	rqst.payload = (u8 *)&data.rqst;

	rsp.capacity = sizeof(struct surface_sam_sid_vhf_meta_resp);
	rsp.length = 0;
	rsp.pointer = (u8 *)&data;

	status = ssam_request_sync(sdev->ctrl, &rqst, &rsp);
	if (status)
		return status;

	*meta = data.data.meta;

	return 0;
}

static int vhf_get_hid_descriptor(struct ssam_device *sdev, u8 **desc, int *size)
{
	struct surface_sam_sid_vhf_meta_resp data = {};
	struct ssam_request rqst;
	struct ssam_response rsp;
	int status, len;
	u8 *buf;

	data.rqst.id = 0;
	data.rqst.offset = 0;
	data.rqst.length = 0x76;
	data.rqst.end = 0;

	rqst.target_category = sdev->uid.category;
	rqst.target_id = sdev->uid.target;;
	rqst.command_id = 0x04;
	rqst.instance_id = sdev->uid.instance;
	rqst.flags = SSAM_REQUEST_HAS_RESPONSE;
	rqst.length = sizeof(struct surface_sam_sid_vhf_meta_rqst);
	rqst.payload = (u8 *)&data.rqst;

	rsp.capacity = sizeof(struct surface_sam_sid_vhf_meta_resp);
	rsp.length = 0;
	rsp.pointer = (u8 *)&data;

	// first fetch 00 to get the total length
	status = ssam_request_sync(sdev->ctrl, &rqst, &rsp);
	if (status)
		return status;

	len = data.data.info.hid_len;

	// allocate a buffer for the descriptor
	buf = kzalloc(len, GFP_KERNEL);

	// then, iterate and write into buffer, copying out bytes
	data.rqst.id = 1;
	data.rqst.offset = 0;
	data.rqst.length = 0x76;
	data.rqst.end = 0;

	while (!data.rqst.end && data.rqst.offset < len) {
		status = ssam_request_sync(sdev->ctrl, &rqst, &rsp);
		if (status) {
			kfree(buf);
			return status;
		}
		memcpy(buf + data.rqst.offset, data.data.pld, data.rqst.length);

		data.rqst.offset += data.rqst.length;
	}

	*desc = buf;
	*size = len;

	return 0;
}

static int sid_vhf_hid_parse(struct hid_device *hid)
{
	struct sid_vhf *vhf = dev_get_drvdata(hid->dev.parent);
	int ret = 0, size;
	u8 *buf;

	ret = vhf_get_hid_descriptor(vhf->sdev, &buf, &size);
	if (ret != 0) {
		hid_err(hid, "Failed to read HID descriptor from device: %d\n", ret);
		return -EIO;
	}
	hid_dbg(hid, "HID descriptor of device:");
	print_hex_dump_debug("descriptor:", DUMP_PREFIX_OFFSET, 16, 1, buf, size, false);

	ret = hid_parse_report(hid, buf, size);
	kfree(buf);
	return ret;

}

static int sid_vhf_hid_raw_request(struct hid_device *hid, unsigned char
		reportnum, u8 *buf, size_t len, unsigned char rtype, int
		reqtype)
{
	struct sid_vhf *vhf = dev_get_drvdata(hid->dev.parent);
	struct ssam_request rqst;
	struct ssam_response rsp;
	int status;
	u8 cid;

	hid_dbg(hid, "%s: reportnum=%#04x rtype=%i reqtype=%i\n", __func__, reportnum, rtype, reqtype);
	print_hex_dump_debug("report:", DUMP_PREFIX_OFFSET, 16, 1, buf, len, false);

	// Byte 0 is the report number. Report data starts at byte 1.
	buf[0] = reportnum;

	switch (rtype) {
	case HID_OUTPUT_REPORT:
		cid = 0x01;
		break;
	case HID_FEATURE_REPORT:
		switch (reqtype) {
		case HID_REQ_GET_REPORT:
			// The EC doesn't respond to GET FEATURE for these touchpad reports
			// we immediately discard to avoid waiting for a timeout.
			if (reportnum == 6 || reportnum == 7 || reportnum == 8 || reportnum == 9 || reportnum == 0x0b) {
				hid_dbg(hid, "%s: skipping get feature report for 0x%02x\n", __func__, reportnum);
				return 0;
			}

			cid = 0x02;
			break;
		case HID_REQ_SET_REPORT:
			cid = 0x03;
			break;
		default:
			hid_err(hid, "%s: unknown req type 0x%02x\n", __func__, rtype);
			return -EIO;
		}
		break;
	default:
		hid_err(hid, "%s: unknown report type 0x%02x\n", __func__, reportnum);
		return -EIO;
	}

	rqst.target_category = vhf->sdev->uid.category;
	rqst.target_id = vhf->sdev->uid.target;
	rqst.instance_id = vhf->sdev->uid.instance;
	rqst.command_id = cid;
	rqst.flags = reqtype == HID_REQ_GET_REPORT ? SSAM_REQUEST_HAS_RESPONSE : 0;
	rqst.length = reqtype == HID_REQ_GET_REPORT ? 1 : len;
	rqst.payload = buf;

	rsp.capacity = len;
	rsp.length = 0;
	rsp.pointer = buf;

	hid_dbg(hid, "%s: sending to cid=%#04x snc=%#04x\n", __func__, cid, HID_REQ_GET_REPORT == reqtype);

	status = ssam_request_sync(vhf->sdev->ctrl, &rqst, &rsp);
	hid_dbg(hid, "%s: status %i\n", __func__, status);

	if (status)
		return status;

	if (rsp.length > 0)
		print_hex_dump_debug("response:", DUMP_PREFIX_OFFSET, 16, 1, rsp.pointer, rsp.length, false);

	return rsp.length;
}

static struct hid_ll_driver sid_vhf_hid_ll_driver = {
	.start         = sid_vhf_hid_start,
	.stop          = sid_vhf_hid_stop,
	.open          = sid_vhf_hid_open,
	.close         = sid_vhf_hid_close,
	.parse         = sid_vhf_hid_parse,
	.raw_request   = sid_vhf_hid_raw_request,
};


static struct hid_device *sid_vhf_create_hid_device(struct ssam_device *sdev, struct vhf_device_metadata *meta)
{
	struct hid_device *hid;

	hid = hid_allocate_device();
	if (IS_ERR(hid))
		return hid;

	hid->dev.parent = &sdev->dev;

	hid->bus     = BUS_VIRTUAL;
	hid->vendor  = meta->vendor_id;
	hid->product = meta->product_id;

	hid->ll_driver = &sid_vhf_hid_ll_driver;

	sprintf(hid->name, "%s", SID_VHF_INPUT_NAME);

	return hid;
}

static u32 sid_vhf_event_handler(struct ssam_event_notifier *nf, const struct ssam_event *event)
{
	struct sid_vhf *vhf = container_of(nf, struct sid_vhf, notif);
	int status;

	if (event->command_id != 0x00 && event->command_id != 0x03 && event->command_id != 0x04)
		return 0;

	// skip if HID hasn't started yet
	if (!test_bit(VHF_HID_STARTED, &vhf->state))
		return SSAM_NOTIF_HANDLED;

	status = hid_input_report(vhf->hid, HID_INPUT_REPORT, (u8 *)&event->data[0], event->length, 0);
	return ssam_notifier_from_errno(status) | SSAM_NOTIF_HANDLED;
}


#ifdef CONFIG_PM

static int surface_sam_sid_vhf_suspend(struct device *dev)
{
	struct sid_vhf *vhf = dev_get_drvdata(dev);

	if (vhf->hid->driver && vhf->hid->driver->suspend)
		return vhf->hid->driver->suspend(vhf->hid, PMSG_SUSPEND);

	return 0;
}

static int surface_sam_sid_vhf_resume(struct device *dev)
{
	struct sid_vhf *vhf = dev_get_drvdata(dev);

	if (vhf->hid->driver && vhf->hid->driver->resume)
		return vhf->hid->driver->resume(vhf->hid);

	return 0;
}

static int surface_sam_sid_vhf_freeze(struct device *dev)
{
	struct sid_vhf *vhf = dev_get_drvdata(dev);

	if (vhf->hid->driver && vhf->hid->driver->suspend)
		return vhf->hid->driver->suspend(vhf->hid, PMSG_FREEZE);

	return 0;
}

static int surface_sam_sid_vhf_poweroff(struct device *dev)
{
	struct sid_vhf *vhf = dev_get_drvdata(dev);

	if (vhf->hid->driver && vhf->hid->driver->suspend)
		return vhf->hid->driver->suspend(vhf->hid, PMSG_HIBERNATE);

	return 0;
}

static int surface_sam_sid_vhf_restore(struct device *dev)
{
	struct sid_vhf *vhf = dev_get_drvdata(dev);

	if (vhf->hid->driver && vhf->hid->driver->reset_resume)
		return vhf->hid->driver->reset_resume(vhf->hid);

	return 0;
}

struct dev_pm_ops surface_sam_sid_vhf_pm_ops = {
	.freeze   = surface_sam_sid_vhf_freeze,
	.thaw     = surface_sam_sid_vhf_resume,
	.suspend  = surface_sam_sid_vhf_suspend,
	.resume   = surface_sam_sid_vhf_resume,
	.poweroff = surface_sam_sid_vhf_poweroff,
	.restore  = surface_sam_sid_vhf_restore,
};

#else /* CONFIG_PM */

struct dev_pm_ops surface_sam_sid_vhf_pm_ops = { };

#endif /* CONFIG_PM */


static int surface_sam_sid_vhf_probe(struct ssam_device *sdev)
{
	const struct sid_vhf_properties *p;
	struct sid_vhf *vhf;
	struct vhf_device_metadata meta = {};
	struct hid_device *hid;
	int status;

	p = ssam_device_get_match_data(sdev);
	if (!p)
		return -ENODEV;

	vhf = devm_kzalloc(&sdev->dev, sizeof(*vhf), GFP_KERNEL);
	if (!vhf)
		return -ENOMEM;

	status = vhf_get_metadata(sdev, &meta);
	if (status)
		return status;

	hid = sid_vhf_create_hid_device(sdev, &meta);
	if (IS_ERR(hid))
		return PTR_ERR(hid);

	vhf->sdev = sdev;
	vhf->hid = hid;

	vhf->notif.base.priority = 1;
	vhf->notif.base.fn = sid_vhf_event_handler;
	vhf->notif.event.reg = p->registry;
	vhf->notif.event.id.target_category = sdev->uid.category;
	vhf->notif.event.id.instance = sdev->uid.instance;
	vhf->notif.event.mask = SSAM_EVENT_MASK_STRICT;
	vhf->notif.event.flags = 0;

	ssam_device_set_drvdata(sdev, vhf);

	status = ssam_notifier_register(sdev->ctrl, &vhf->notif);
	if (status)
		goto err_notif;

	status = hid_add_device(hid);
	if (status)
		goto err_add_hid;

	return 0;

err_add_hid:
	ssam_notifier_unregister(sdev->ctrl, &vhf->notif);
err_notif:
	hid_destroy_device(hid);
	return status;
}

static void surface_sam_sid_vhf_remove(struct ssam_device *sdev)
{
	struct sid_vhf *vhf = ssam_device_get_drvdata(sdev);

	ssam_notifier_unregister(sdev->ctrl, &vhf->notif);
	hid_destroy_device(vhf->hid);
}

static const struct sid_vhf_properties sid_vhf_default_props = {
	.registry = SSAM_EVENT_REGISTRY_REG,
};

static const struct ssam_device_id surface_sam_sid_vhf_match[] = {
	{
		SSAM_SDEV(HID, SSAM_ANY_TID, SSAM_ANY_IID, 0x00),
		.driver_data = (unsigned long)&sid_vhf_default_props
	},
	{ },
};
MODULE_DEVICE_TABLE(ssam, surface_sam_sid_vhf_match);

static struct ssam_device_driver surface_sam_sid_vhf = {
	.probe = surface_sam_sid_vhf_probe,
	.remove = surface_sam_sid_vhf_remove,
	.match_table = surface_sam_sid_vhf_match,
	.driver = {
		.name = "surface_hid",
		.pm = &surface_sam_sid_vhf_pm_ops,
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};
module_ssam_device_driver(surface_sam_sid_vhf);

MODULE_AUTHOR("Blaž Hrastnik <blaz@mxxn.io>");
MODULE_DESCRIPTION("HID transport-/device-driver for Surface System Aggregator Module");
MODULE_LICENSE("GPL");
