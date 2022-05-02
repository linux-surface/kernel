// SPDX-License-Identifier: GPL-2.0
/*
 *  HID driver for Google Hangouts Meet Speakermic
 *
 *  Copyright 2022 Google LLC.
 */

#include <linux/hid.h>
#include <linux/module.h>

#include "hid-ids.h"

/*
 * This driver handles the telephony phone mute HID usage by ignoring it. This
 * avoids the default handling by the hid-input driver which is to map this to
 * a KEY_MICMUTE event. The issue is that this device implements the phone mute
 * HID usage as a toggle switch, where 1 indicates muted, and 0 indicates
 * unmuted. However, for an EV_KEY event 1 indicates the key has been pressed
 * and 0 indicates it has been released.
 */

static int atrus_event(struct hid_device *hid, struct hid_field *field,
		       struct hid_usage *usage, __s32 value)
{
	/*
	 * Return 1 to indicate no further processing should be done for this
	 * usage.
	 */
	return 1;
}

static const struct hid_device_id atrus_devices[] = {
	{ HID_DEVICE(BUS_USB, HID_GROUP_GENERIC,
		     USB_VENDOR_ID_GOOGLE, USB_DEVICE_ID_GOOGLE_ATRUS) },
	{ }
};
MODULE_DEVICE_TABLE(hid, atrus_devices);

static const struct hid_usage_id atrus_usages[] = {
	/* Handle only the Telephony Phone Mute usage. */
	{ HID_UP_TELEPHONY | 0x2f, EV_KEY, HID_ANY_ID },
	{ HID_TERMINATOR, HID_TERMINATOR, HID_TERMINATOR }
};

static struct hid_driver atrus_driver = {
	.name = "atrus",
	.id_table = atrus_devices,
	.usage_table = atrus_usages,
	.event = atrus_event,
};
module_hid_driver(atrus_driver);

MODULE_AUTHOR("Pablo Ceballos <pcebalos@google.com>");
MODULE_DESCRIPTION("Google Hangouts Meet Speakermic USB HID Driver");
MODULE_LICENSE("GPL");
