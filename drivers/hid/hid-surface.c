// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * HID driver for Microsoft Surface devices
 *
 * Copyright (c) 2025 Linux Surface Project
 */

#include <linux/device.h>
#include <linux/hid.h>
#include <linux/input.h>
#include <linux/module.h>

#include "hid-ids.h"

/*
 * The Surface Aggregator Module firmware incorrectly reports the FN key
 * as BTN_0 (button 256). This button can get stuck in pressed state,
 * flooding the input system and breaking focus tracking in some
 * compositors. Filter out BTN_0 as FN should be handled as a hardware
 * modifier, not reported to the OS.
 */
static int surface_input_mapping(struct hid_device *hdev, struct hid_input *hi,
				  struct hid_field *field, struct hid_usage *usage,
				  unsigned long **bit, int *max)
{
	/*
	 * Filter BTN_0 during input mapping in case it appears in the
	 * HID descriptor (defense in depth).
	 */
	if (usage->type == EV_KEY && usage->code == BTN_0)
		return -1;  /* Don't map this usage */

	return 0;  /* Use default mapping */
}

static int surface_event(struct hid_device *hdev, struct hid_field *field,
			  struct hid_usage *usage, __s32 value)
{
	/*
	 * The Surface Aggregator Module firmware reports the FN key as BTN_0
	 * at runtime. This button can get stuck in pressed state, flooding
	 * the input system and breaking focus tracking. Filter out these
	 * events as FN should be a hardware modifier, not reported to the OS.
	 */
	if (usage->type == EV_KEY && usage->code == BTN_0)
		return 1;  /* Event handled, don't process further */

	return 0;  /* Process event normally */
}

static int surface_probe(struct hid_device *hdev, const struct hid_device_id *id)
{
	int ret;

	ret = hid_parse(hdev);
	if (ret) {
		hid_err(hdev, "parse failed\n");
		return ret;
	}

	ret = hid_hw_start(hdev, HID_CONNECT_DEFAULT);
	if (ret) {
		hid_err(hdev, "hw start failed\n");
		return ret;
	}

	return 0;
}

static const struct hid_device_id surface_devices[] = {
	{ HID_DEVICE(BUS_HOST, HID_GROUP_GENERIC,
		     USB_VENDOR_ID_MICROSOFT, 0x09AE) },  /* Surface Keyboard */
	{ HID_DEVICE(BUS_HOST, HID_GROUP_GENERIC,
		     USB_VENDOR_ID_MICROSOFT, 0x09AF) },  /* Surface Mouse/Touchpad */
	{ }
};
MODULE_DEVICE_TABLE(hid, surface_devices);

static struct hid_driver surface_driver = {
	.name = "surface",
	.id_table = surface_devices,
	.probe = surface_probe,
	.input_mapping = surface_input_mapping,
	.event = surface_event,
};
module_hid_driver(surface_driver);

MODULE_AUTHOR("Linux Surface Project");
MODULE_DESCRIPTION("Microsoft Surface HID driver");
MODULE_LICENSE("GPL");
