// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Dorian Stoll
 *
 * Linux driver for Intel Precise Touch & Stylus
 */

#include <linux/err.h>
#include <linux/gfp.h>
#include <linux/hid.h>
#include <linux/slab.h>
#include <linux/types.h>

#include "context.h"
#include "control.h"
#include "desc.h"
#include "eds1.h"
#include "spec-device.h"

int ipts_eds1_get_descriptor(struct ipts_context *ipts, u8 **desc_buffer, size_t *desc_size)
{
	size_t size = 0;
	u8 *buffer = NULL;

	if (!ipts)
		return -EFAULT;

	if (!desc_buffer)
		return -EFAULT;

	if (!desc_size)
		return -EFAULT;

	size = sizeof(ipts_singletouch_descriptor) + sizeof(ipts_fallback_descriptor);

	buffer = kzalloc(size, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	memcpy(buffer, ipts_singletouch_descriptor, sizeof(ipts_singletouch_descriptor));
	memcpy(&buffer[sizeof(ipts_singletouch_descriptor)], ipts_fallback_descriptor,
	       sizeof(ipts_fallback_descriptor));

	*desc_size = size;
	*desc_buffer = buffer;

	return 0;
}

static int ipts_eds1_switch_mode(struct ipts_context *ipts, enum ipts_mode mode)
{
	int ret = 0;

	if (!ipts)
		return -EFAULT;

	if (ipts->mode == mode)
		return 0;

	ipts->mode = mode;

	ret = ipts_control_restart(ipts);
	if (ret)
		dev_err(ipts->dev, "Failed to switch modes: %d\n", ret);

	return ret;
}

int ipts_eds1_raw_request(struct ipts_context *ipts, u8 *buffer, size_t size, u8 report_id,
			  enum hid_report_type report_type, enum hid_class_request request_type)
{
	int ret = 0;

	if (!ipts)
		return -EFAULT;

	if (!buffer)
		return -EFAULT;

	if (report_id != IPTS_HID_REPORT_SET_MODE)
		return -EIO;

	if (report_type != HID_FEATURE_REPORT)
		return -EIO;

	if (size != 2)
		return -EINVAL;

	/*
	 * Implement mode switching report for older devices without native HID support.
	 */

	if (request_type == HID_REQ_GET_REPORT) {
		memset(buffer, 0, size);
		buffer[0] = report_id;
		buffer[1] = ipts->mode;
	} else if (request_type == HID_REQ_SET_REPORT) {
		return ipts_eds1_switch_mode(ipts, buffer[1]);
	} else {
		return -EIO;
	}

	return ret;
}
