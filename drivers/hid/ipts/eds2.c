// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Dorian Stoll
 *
 * Linux driver for Intel Precise Touch & Stylus
 */

#include <linux/completion.h>
#include <linux/err.h>
#include <linux/gfp.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/types.h>

#include "context.h"
#include "control.h"
#include "desc.h"
#include "eds2.h"
#include "spec-data.h"

int ipts_eds2_get_descriptor(struct ipts_context *ipts, u8 **desc_buffer, size_t *desc_size)
{
	size_t size = 0;
	u8 *buffer = NULL;

	if (!ipts)
		return -EFAULT;

	if (!desc_buffer)
		return -EFAULT;

	if (!desc_size)
		return -EFAULT;

	size = sizeof(ipts_singletouch_descriptor) + ipts->descriptor.size;

	buffer = kzalloc(size, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	memcpy(buffer, ipts_singletouch_descriptor, sizeof(ipts_singletouch_descriptor));
	memcpy(&buffer[sizeof(ipts_singletouch_descriptor)], ipts->descriptor.address,
	       ipts->descriptor.size);

	*desc_size = size;
	*desc_buffer = buffer;

	return 0;
}

static int ipts_eds2_get_feature(struct ipts_context *ipts, u8 *buffer, size_t size, u8 report_id,
				 enum ipts_feedback_data_type type)
{
	int ret = 0;

	if (!ipts)
		return -EFAULT;

	if (!buffer)
		return -EFAULT;

	mutex_lock(&ipts->feature_lock);

	memset(buffer, 0, size);
	buffer[0] = report_id;

	memset(&ipts->feature_report, 0, sizeof(ipts->feature_report));
	reinit_completion(&ipts->feature_event);

	ret = ipts_control_hid2me_feedback(ipts, IPTS_FEEDBACK_CMD_TYPE_NONE, type, buffer, size);
	if (ret) {
		dev_err(ipts->dev, "Failed to send hid2me feedback: %d\n", ret);
		goto out;
	}

	ret = wait_for_completion_timeout(&ipts->feature_event, msecs_to_jiffies(5000));
	if (ret == 0) {
		dev_warn(ipts->dev, "GET_FEATURES timed out!\n");
		ret = -EIO;
		goto out;
	}

	if (!ipts->feature_report.address) {
		ret = -EFAULT;
		goto out;
	}

	if (ipts->feature_report.size > size) {
		ret = -ETOOSMALL;
		goto out;
	}

	ret = ipts->feature_report.size;
	memcpy(buffer, ipts->feature_report.address, ipts->feature_report.size);

out:
	mutex_unlock(&ipts->feature_lock);
	return ret;
}

static int ipts_eds2_set_feature(struct ipts_context *ipts, u8 *buffer, size_t size, u8 report_id,
				 enum ipts_feedback_data_type type)
{
	int ret = 0;

	if (!ipts)
		return -EFAULT;

	if (!buffer)
		return -EFAULT;

	buffer[0] = report_id;

	ret = ipts_control_hid2me_feedback(ipts, IPTS_FEEDBACK_CMD_TYPE_NONE, type, buffer, size);
	if (ret)
		dev_err(ipts->dev, "Failed to send hid2me feedback: %d\n", ret);

	return ret;
}

int ipts_eds2_raw_request(struct ipts_context *ipts, u8 *buffer, size_t size, u8 report_id,
			  enum hid_report_type report_type, enum hid_class_request request_type)
{
	enum ipts_feedback_data_type feedback_type = IPTS_FEEDBACK_DATA_TYPE_VENDOR;

	if (!ipts)
		return -EFAULT;

	if (!buffer)
		return -EFAULT;

	if (report_type == HID_OUTPUT_REPORT && request_type == HID_REQ_SET_REPORT)
		feedback_type = IPTS_FEEDBACK_DATA_TYPE_OUTPUT_REPORT;
	else if (report_type == HID_FEATURE_REPORT && request_type == HID_REQ_GET_REPORT)
		feedback_type = IPTS_FEEDBACK_DATA_TYPE_GET_FEATURES;
	else if (report_type == HID_FEATURE_REPORT && request_type == HID_REQ_SET_REPORT)
		feedback_type = IPTS_FEEDBACK_DATA_TYPE_SET_FEATURES;
	else
		return -EIO;

	if (request_type == HID_REQ_GET_REPORT)
		return ipts_eds2_get_feature(ipts, buffer, size, report_id, feedback_type);
	else
		return ipts_eds2_set_feature(ipts, buffer, size, report_id, feedback_type);
}
