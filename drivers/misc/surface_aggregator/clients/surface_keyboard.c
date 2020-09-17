// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Surface System Aggregator Module (SSAM) legacy HID input device driver.
 *
 * Provides support for the legacy HID keyboard device found on the Surface
 * Laptop 1 and 2.
 */

#include <linux/acpi.h>
#include <linux/hid.h>
#include <linux/input.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/types.h>

#include <linux/surface_aggregator/controller.h>


#define USB_VENDOR_ID_MICROSOFT		0x045e
#define USB_DEVICE_ID_MS_VHF		0xf001

#define VHF_INPUT_NAME			"Microsoft Virtual HID Framework Device"


struct vhf_drvdata {
	struct platform_device *dev;
	struct ssam_controller *ctrl;

	struct ssam_event_notifier notif;

	struct hid_device *hid;
};


/*
 * These report descriptors have been extracted from a Surface Book 2.
 * They seems to be similar enough to be usable on the Surface Laptop.
 */
static const u8 vhf_hid_desc[] = {
	// keyboard descriptor (event command ID 0x03)
	0x05, 0x01,             /*  Usage Page (Desktop),                   */
	0x09, 0x06,             /*  Usage (Keyboard),                       */
	0xA1, 0x01,             /*  Collection (Application),               */
	0x85, 0x01,             /*      Report ID (1),                      */
	0x15, 0x00,             /*      Logical Minimum (0),                */
	0x25, 0x01,             /*      Logical Maximum (1),                */
	0x75, 0x01,             /*      Report Size (1),                    */
	0x95, 0x08,             /*      Report Count (8),                   */
	0x05, 0x07,             /*      Usage Page (Keyboard),              */
	0x19, 0xE0,             /*      Usage Minimum (KB Leftcontrol),     */
	0x29, 0xE7,             /*      Usage Maximum (KB Right GUI),       */
	0x81, 0x02,             /*      Input (Variable),                   */
	0x75, 0x08,             /*      Report Size (8),                    */
	0x95, 0x0A,             /*      Report Count (10),                  */
	0x19, 0x00,             /*      Usage Minimum (None),               */
	0x29, 0x91,             /*      Usage Maximum (KB LANG2),           */
	0x26, 0xFF, 0x00,       /*      Logical Maximum (255),              */
	0x81, 0x00,             /*      Input,                              */
	0x05, 0x0C,             /*      Usage Page (Consumer),              */
	0x0A, 0xC0, 0x02,       /*      Usage (02C0h),                      */
	0xA1, 0x02,             /*      Collection (Logical),               */
	0x1A, 0xC1, 0x02,       /*          Usage Minimum (02C1h),          */
	0x2A, 0xC6, 0x02,       /*          Usage Maximum (02C6h),          */
	0x95, 0x06,             /*          Report Count (6),               */
	0xB1, 0x03,             /*          Feature (Constant, Variable),   */
	0xC0,                   /*      End Collection,                     */
	0x05, 0x08,             /*      Usage Page (LED),                   */
	0x19, 0x01,             /*      Usage Minimum (01h),                */
	0x29, 0x03,             /*      Usage Maximum (03h),                */
	0x75, 0x01,             /*      Report Size (1),                    */
	0x95, 0x03,             /*      Report Count (3),                   */
	0x25, 0x01,             /*      Logical Maximum (1),                */
	0x91, 0x02,             /*      Output (Variable),                  */
	0x95, 0x05,             /*      Report Count (5),                   */
	0x91, 0x01,             /*      Output (Constant),                  */
	0xC0,                   /*  End Collection,                         */

	// media key descriptor (event command ID 0x04)
	0x05, 0x0C,             /*  Usage Page (Consumer),                  */
	0x09, 0x01,             /*  Usage (Consumer Control),               */
	0xA1, 0x01,             /*  Collection (Application),               */
	0x85, 0x03,             /*      Report ID (3),                      */
	0x75, 0x10,             /*      Report Size (16),                   */
	0x15, 0x00,             /*      Logical Minimum (0),                */
	0x26, 0xFF, 0x03,       /*      Logical Maximum (1023),             */
	0x19, 0x00,             /*      Usage Minimum (00h),                */
	0x2A, 0xFF, 0x03,       /*      Usage Maximum (03FFh),              */
	0x81, 0x00,             /*      Input,                              */
	0xC0,                   /*  End Collection,                         */
};


static int vhf_hid_start(struct hid_device *hid)
{
	hid_dbg(hid, "%s\n", __func__);
	return 0;
}

static void vhf_hid_stop(struct hid_device *hid)
{
	hid_dbg(hid, "%s\n", __func__);
}

static int vhf_hid_open(struct hid_device *hid)
{
	hid_dbg(hid, "%s\n", __func__);
	return 0;
}

static void vhf_hid_close(struct hid_device *hid)
{
	hid_dbg(hid, "%s\n", __func__);
}

static int vhf_hid_parse(struct hid_device *hid)
{
	return hid_parse_report(hid, (u8 *)vhf_hid_desc, ARRAY_SIZE(vhf_hid_desc));
}

static int vhf_hid_raw_request(struct hid_device *hid, unsigned char reportnum,
			       u8 *buf, size_t len, unsigned char rtype,
			       int reqtype)
{
	hid_dbg(hid, "%s\n", __func__);
	return 0;
}

static int vhf_hid_output_report(struct hid_device *hid, u8 *buf, size_t len)
{
	hid_dbg(hid, "%s\n", __func__);
	print_hex_dump_debug("report:", DUMP_PREFIX_OFFSET, 16, 1, buf, len, false);

	return len;
}

static struct hid_ll_driver vhf_hid_ll_driver = {
	.start         = vhf_hid_start,
	.stop          = vhf_hid_stop,
	.open          = vhf_hid_open,
	.close         = vhf_hid_close,
	.parse         = vhf_hid_parse,
	.raw_request   = vhf_hid_raw_request,
	.output_report = vhf_hid_output_report,
};


static struct hid_device *vhf_create_hid_device(struct platform_device *pdev)
{
	struct hid_device *hid;

	hid = hid_allocate_device();
	if (IS_ERR(hid))
		return hid;

	hid->dev.parent = &pdev->dev;

	hid->bus     = BUS_VIRTUAL;
	hid->vendor  = USB_VENDOR_ID_MICROSOFT;
	hid->product = USB_DEVICE_ID_MS_VHF;

	hid->ll_driver = &vhf_hid_ll_driver;

	sprintf(hid->name, "%s", VHF_INPUT_NAME);

	return hid;
}

static u32 vhf_event_handler(struct ssam_event_notifier *nf, const struct ssam_event *event)
{
	struct vhf_drvdata *drvdata = container_of(nf, struct vhf_drvdata, notif);
	int status;

	if (event->command_id == 0x03 || event->command_id == 0x04) {
		status = hid_input_report(drvdata->hid, HID_INPUT_REPORT, (u8 *)&event->data[0], event->length, 1);
		return ssam_notifier_from_errno(status) | SSAM_NOTIF_HANDLED;
	}

	return 0;
}


#ifdef CONFIG_PM

static int surface_sam_vhf_suspend(struct device *dev)
{
	struct vhf_drvdata *d = dev_get_drvdata(dev);

	if (d->hid->driver && d->hid->driver->suspend)
		return d->hid->driver->suspend(d->hid, PMSG_SUSPEND);

	return 0;
}

static int surface_sam_vhf_resume(struct device *dev)
{
	struct vhf_drvdata *d = dev_get_drvdata(dev);

	if (d->hid->driver && d->hid->driver->resume)
		return d->hid->driver->resume(d->hid);

	return 0;
}

static int surface_sam_vhf_freeze(struct device *dev)
{
	struct vhf_drvdata *d = dev_get_drvdata(dev);

	if (d->hid->driver && d->hid->driver->suspend)
		return d->hid->driver->suspend(d->hid, PMSG_FREEZE);

	return 0;
}

static int surface_sam_vhf_poweroff(struct device *dev)
{
	struct vhf_drvdata *d = dev_get_drvdata(dev);

	if (d->hid->driver && d->hid->driver->suspend)
		return d->hid->driver->suspend(d->hid, PMSG_HIBERNATE);

	return 0;
}

static int surface_sam_vhf_restore(struct device *dev)
{
	struct vhf_drvdata *d = dev_get_drvdata(dev);

	if (d->hid->driver && d->hid->driver->reset_resume)
		return d->hid->driver->reset_resume(d->hid);

	return 0;
}

struct dev_pm_ops surface_sam_vhf_pm_ops = {
	.freeze   = surface_sam_vhf_freeze,
	.thaw     = surface_sam_vhf_resume,
	.suspend  = surface_sam_vhf_suspend,
	.resume   = surface_sam_vhf_resume,
	.poweroff = surface_sam_vhf_poweroff,
	.restore  = surface_sam_vhf_restore,
};

#else /* CONFIG_PM */

struct dev_pm_ops surface_sam_vhf_pm_ops = { };

#endif /* CONFIG_PM */


static int surface_sam_vhf_probe(struct platform_device *pdev)
{
	struct ssam_controller *ctrl;
	struct vhf_drvdata *drvdata;
	struct hid_device *hid;
	int status;

	// add device link to EC
	status = ssam_client_bind(&pdev->dev, &ctrl);
	if (status)
		return status == -ENXIO ? -EPROBE_DEFER : status;

	drvdata = devm_kzalloc(&pdev->dev, sizeof(*drvdata), GFP_KERNEL);
	if (!drvdata)
		return -ENOMEM;

	hid = vhf_create_hid_device(pdev);
	if (IS_ERR(hid))
		return PTR_ERR(hid);

	status = hid_add_device(hid);
	if (status)
		goto err_add_hid;

	drvdata->dev = pdev;
	drvdata->ctrl = ctrl;
	drvdata->hid = hid;

	drvdata->notif.base.priority = 1;
	drvdata->notif.base.fn = vhf_event_handler;
	drvdata->notif.event.reg = SSAM_EVENT_REGISTRY_SAM;
	drvdata->notif.event.id.target_category = SSAM_SSH_TC_KBD;
	drvdata->notif.event.id.instance = 0;
	drvdata->notif.event.mask = SSAM_EVENT_MASK_NONE;
	drvdata->notif.event.flags = 0;

	platform_set_drvdata(pdev, drvdata);

	status = ssam_notifier_register(ctrl, &drvdata->notif);
	if (status)
		goto err_add_hid;

	return 0;

err_add_hid:
	hid_destroy_device(hid);
	return status;
}

static int surface_sam_vhf_remove(struct platform_device *pdev)
{
	struct vhf_drvdata *drvdata = platform_get_drvdata(pdev);

	ssam_notifier_unregister(drvdata->ctrl, &drvdata->notif);
	hid_destroy_device(drvdata->hid);

	return 0;
}


static const struct acpi_device_id surface_sam_vhf_match[] = {
	{ "MSHW0096" },
	{ },
};
MODULE_DEVICE_TABLE(acpi, surface_sam_vhf_match);

static struct platform_driver surface_sam_vhf = {
	.probe = surface_sam_vhf_probe,
	.remove = surface_sam_vhf_remove,
	.driver = {
		.name = "surface_keyboard",
		.acpi_match_table = surface_sam_vhf_match,
		.pm = &surface_sam_vhf_pm_ops,
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};
module_platform_driver(surface_sam_vhf);

MODULE_AUTHOR("Maximilian Luz <luzmaximilian@gmail.com>");
MODULE_DESCRIPTION("Legacy HID keyboard driver for Surface System Aggregator Module");
MODULE_LICENSE("GPL");
