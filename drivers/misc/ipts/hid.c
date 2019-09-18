// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 * Intel Precise Touch & Stylus
 * Copyright (c) 2016 Intel Corporation
 *
 */

#include <linux/dmi.h>
#include <linux/firmware.h>
#include <linux/hid.h>
#include <linux/ipts.h>
#include <linux/module.h>
#include <linux/vmalloc.h>

#include "companion.h"
#include "hid.h"
#include "ipts.h"
#include "msg-handler.h"
#include "params.h"
#include "resource.h"
#include "sensor-regs.h"

#define HID_DESC_INTEL  "intel_desc.bin"
#define HID_DESC_VENDOR "vendor_desc.bin"

enum output_buffer_payload_type {
	OUTPUT_BUFFER_PAYLOAD_ERROR = 0,
	OUTPUT_BUFFER_PAYLOAD_HID_INPUT_REPORT,
	OUTPUT_BUFFER_PAYLOAD_HID_FEATURE_REPORT,
	OUTPUT_BUFFER_PAYLOAD_KERNEL_LOAD,
	OUTPUT_BUFFER_PAYLOAD_FEEDBACK_BUFFER
};

struct kernel_output_buffer_header {
	u16 length;
	u8 payload_type;
	u8 reserved1;
	struct touch_hid_private_data hid_private_data;
	u8 reserved2[28];
	u8 data[0];
};

struct kernel_output_payload_error {
	u16 severity;
	u16 source;
	u8 code[4];
	char string[128];
};

static int ipts_hid_get_descriptor(struct ipts_info *ipts,
		u8 **desc, int *size)
{
	u8 *buf;
	int hid_size = 0, ret = 0;
	const struct firmware *intel_desc = NULL;
	const struct firmware *vendor_desc = NULL;

	ret = ipts_request_firmware(&intel_desc, HID_DESC_INTEL,
		&ipts->cldev->dev);
	if (ret)
		goto no_hid;

	hid_size = intel_desc->size;

	ret = ipts_request_firmware(&vendor_desc, HID_DESC_VENDOR,
			&ipts->cldev->dev);
	if (ret)
		ipts_dbg(ipts, "error in reading HID Vendor Descriptor\n");
	else
		hid_size += vendor_desc->size;

	ipts_dbg(ipts, "HID descriptor size = %d\n", hid_size);

	buf = vmalloc(hid_size);
	if (buf == NULL) {
		ret = -ENOMEM;
		goto no_mem;
	}

	memcpy(buf, intel_desc->data, intel_desc->size);
	if (vendor_desc) {
		memcpy(&buf[intel_desc->size], vendor_desc->data,
			vendor_desc->size);
		release_firmware(vendor_desc);
	}
	release_firmware(intel_desc);

	*desc = buf;
	*size = hid_size;

	return 0;

no_mem:
	if (vendor_desc)
		release_firmware(vendor_desc);

	release_firmware(intel_desc);

no_hid:
	return ret;
}

static int ipts_hid_parse(struct hid_device *hid)
{
	struct ipts_info *ipts = hid->driver_data;
	int ret = 0, size;
	u8 *buf;

	ipts_dbg(ipts, "%s() start\n", __func__);

	ret = ipts_hid_get_descriptor(ipts, &buf, &size);
	if (ret != 0) {
		ipts_dbg(ipts, "ipts_hid_get_descriptor: %d\n",
			ret);
		return -EIO;
	}

	ret = hid_parse_report(hid, buf, size);
	vfree(buf);
	if (ret) {
		ipts_err(ipts, "hid_parse_report error : %d\n", ret);
		return ret;
	}

	ipts->hid_desc_ready = true;

	return 0;
}

static int ipts_hid_start(struct hid_device *hid)
{
	return 0;
}

static void ipts_hid_stop(struct hid_device *hid)
{

}

static int ipts_hid_open(struct hid_device *hid)
{
	return 0;
}

static void ipts_hid_close(struct hid_device *hid)
{
	struct ipts_info *ipts = hid->driver_data;

	ipts->hid_desc_ready = false;
}

static int ipts_hid_send_hid2me_feedback(struct ipts_info *ipts,
		u32 fb_data_type, __u8 *buf, size_t count)
{
	struct ipts_buffer_info *fb_buf;
	struct touch_feedback_hdr *feedback;
	enum ipts_state state;
	u8 *payload;
	int header_size;

	header_size = sizeof(struct touch_feedback_hdr);

	if (count > ipts->resource.hid2me_buffer_size - header_size)
		return -EINVAL;

	state = ipts_get_state(ipts);
	if (state != IPTS_STA_RAW_DATA_STARTED &&
			state != IPTS_STA_HID_STARTED)
		return 0;

	fb_buf = ipts_get_hid2me_buffer(ipts);
	feedback = (struct touch_feedback_hdr *)fb_buf->addr;
	payload = fb_buf->addr + header_size;
	memset(feedback, 0, header_size);

	feedback->feedback_data_type = fb_data_type;
	feedback->feedback_cmd_type = TOUCH_FEEDBACK_CMD_TYPE_NONE;
	feedback->payload_size_bytes = count;
	feedback->buffer_id = TOUCH_HID_2_ME_BUFFER_ID;
	feedback->protocol_ver = 0;
	feedback->reserved[0] = 0xAC;

	// copy payload
	memcpy(payload, buf, count);

	ipts_send_feedback(ipts, TOUCH_HID_2_ME_BUFFER_ID, 0);

	return 0;
}

static int ipts_hid_raw_request(struct hid_device *hid,
		unsigned char report_number, __u8 *buf, size_t count,
		unsigned char report_type, int reqtype)
{
	struct ipts_info *ipts = hid->driver_data;
	u32 fb_data_type;

	ipts_dbg(ipts, "hid raw request => report %d, request %d\n",
		(int)report_type, reqtype);

	if (report_type != HID_FEATURE_REPORT)
		return 0;

	switch (reqtype) {
	case HID_REQ_GET_REPORT:
		fb_data_type = TOUCH_FEEDBACK_DATA_TYPE_GET_FEATURES;
		break;
	case HID_REQ_SET_REPORT:
		fb_data_type = TOUCH_FEEDBACK_DATA_TYPE_SET_FEATURES;
		break;
	default:
		ipts_err(ipts, "raw request not supprted: %d\n", reqtype);
		return -EIO;
	}

	return ipts_hid_send_hid2me_feedback(ipts, fb_data_type, buf, count);
}

static int ipts_hid_output_report(struct hid_device *hid,
		__u8 *buf, size_t count)
{
	struct ipts_info *ipts = hid->driver_data;
	u32 fb_data_type;

	ipts_dbg(ipts, "hid output report\n");

	fb_data_type = TOUCH_FEEDBACK_DATA_TYPE_OUTPUT_REPORT;

	return ipts_hid_send_hid2me_feedback(ipts, fb_data_type, buf, count);
}

static struct hid_ll_driver ipts_hid_ll_driver = {
	.parse = ipts_hid_parse,
	.start = ipts_hid_start,
	.stop = ipts_hid_stop,
	.open = ipts_hid_open,
	.close = ipts_hid_close,
	.raw_request = ipts_hid_raw_request,
	.output_report = ipts_hid_output_report,
};

int ipts_hid_init(struct ipts_info *ipts)
{
	int ret = 0;
	struct hid_device *hid;

	hid = hid_allocate_device();
	if (IS_ERR(hid))
		return PTR_ERR(hid);

	hid->driver_data = ipts;
	hid->ll_driver = &ipts_hid_ll_driver;
	hid->dev.parent = &ipts->cldev->dev;
	hid->bus = BUS_MEI;
	hid->version = ipts->device_info.fw_rev;
	hid->vendor = ipts->device_info.vendor_id;
	hid->product = ipts->device_info.device_id;

	snprintf(hid->phys, sizeof(hid->phys), "heci3");
	snprintf(hid->name, sizeof(hid->name),
		"ipts %04hX:%04hX", hid->vendor, hid->product);

	ret = hid_add_device(hid);
	if (ret) {
		if (ret != -ENODEV)
			ipts_err(ipts, "can't add hid device: %d\n", ret);

		hid_destroy_device(hid);

		return ret;
	}

	ipts->hid = hid;

	return 0;
}

void ipts_hid_release(struct ipts_info *ipts)
{
	if (!ipts->hid)
		return;

	hid_destroy_device(ipts->hid);
}

int ipts_handle_hid_data(struct ipts_info *ipts,
		struct touch_sensor_hid_ready_for_data_rsp_data *hid_rsp)
{
	struct touch_raw_data_hdr *raw_header;
	struct ipts_buffer_info *buffer_info;
	struct touch_feedback_hdr *feedback;
	u8 *raw_data;
	int touch_data_buffer_index;
	int transaction_id;
	int ret = 0;

	touch_data_buffer_index = (int)hid_rsp->touch_data_buffer_index;
	buffer_info = ipts_get_touch_data_buffer_hid(ipts);
	raw_header = (struct touch_raw_data_hdr *)buffer_info->addr;
	transaction_id = raw_header->hid_private_data.transaction_id;
	raw_data = (u8 *)raw_header + sizeof(struct touch_raw_data_hdr);

	switch (raw_header->data_type) {
	case TOUCH_RAW_DATA_TYPE_HID_REPORT: {
		memcpy(ipts->hid_input_report, raw_data,
			raw_header->raw_data_size_bytes);

		ret = hid_input_report(ipts->hid, HID_INPUT_REPORT,
			(u8 *)ipts->hid_input_report,
			raw_header->raw_data_size_bytes, 1);
		if (ret)
			ipts_err(ipts, "error in hid_input_report: %d\n", ret);

		break;
	}
	case TOUCH_RAW_DATA_TYPE_GET_FEATURES: {
		// TODO: implement together with "get feature ioctl"
		break;
	}
	case TOUCH_RAW_DATA_TYPE_ERROR: {
		struct touch_error *touch_err = (struct touch_error *)raw_data;

		ipts_err(ipts, "error type: %d, me error: %x, err reg: %x\n",
			touch_err->touch_error_type,
			touch_err->touch_me_fw_error.value,
			touch_err->touch_error_register.reg_value);

		break;
	}
	default:
		break;
	}

	// send feedback data for HID mode
	buffer_info = ipts_get_feedback_buffer(ipts, touch_data_buffer_index);
	feedback = (struct touch_feedback_hdr *)buffer_info->addr;
	memset(feedback, 0, sizeof(struct touch_feedback_hdr));
	feedback->feedback_cmd_type = TOUCH_FEEDBACK_CMD_TYPE_NONE;
	feedback->payload_size_bytes = 0;
	feedback->buffer_id = touch_data_buffer_index;
	feedback->protocol_ver = 0;
	feedback->reserved[0] = 0xAC;

	ret = ipts_send_feedback(ipts, touch_data_buffer_index, transaction_id);

	return ret;
}

static int handle_outputs(struct ipts_info *ipts, int parallel_idx)
{
	struct kernel_output_buffer_header *out_buf_hdr;
	struct ipts_buffer_info *output_buf, *fb_buf = NULL;
	u8 *input_report, *payload;
	u32 tr_id;
	int i, payload_size, ret = 0, header_size;

	header_size = sizeof(struct kernel_output_buffer_header);
	output_buf = ipts_get_output_buffers_by_parallel_id(ipts,
			parallel_idx);

	for (i = 0; i < ipts->resource.num_of_outputs; i++) {
		out_buf_hdr = (struct kernel_output_buffer_header *)
			output_buf[i].addr;

		if (out_buf_hdr->length < header_size)
			continue;

		payload_size = out_buf_hdr->length - header_size;
		payload = out_buf_hdr->data;

		switch (out_buf_hdr->payload_type) {
		case OUTPUT_BUFFER_PAYLOAD_HID_INPUT_REPORT: {
			input_report = ipts->hid_input_report;
			memcpy(input_report, payload, payload_size);

			hid_input_report(ipts->hid, HID_INPUT_REPORT,
				input_report, payload_size, 1);

			break;
		}
		case OUTPUT_BUFFER_PAYLOAD_HID_FEATURE_REPORT: {
			ipts_dbg(ipts, "output hid feature report\n");
			break;
		}
		case OUTPUT_BUFFER_PAYLOAD_KERNEL_LOAD: {
			ipts_dbg(ipts, "output kernel load\n");
			break;
		}
		case OUTPUT_BUFFER_PAYLOAD_FEEDBACK_BUFFER: {
			// send feedback data for raw data mode
			fb_buf = ipts_get_feedback_buffer(ipts, parallel_idx);
			tr_id = out_buf_hdr->hid_private_data.transaction_id;

			memcpy(fb_buf->addr, payload, payload_size);

			break;
		}
		case OUTPUT_BUFFER_PAYLOAD_ERROR: {
			struct kernel_output_payload_error *err_payload;

			if (payload_size == 0)
				break;

			err_payload = (struct kernel_output_payload_error *)
					payload;

			ipts_err(ipts, "severity: %d, source: %d ",
					err_payload->severity,
					err_payload->source);
			ipts_err(ipts, "code : %d:%d:%d:%d\nstring %s\n",
					err_payload->code[0],
					err_payload->code[1],
					err_payload->code[2],
					err_payload->code[3],
					err_payload->string);

			break;
		}
		default:
			ipts_err(ipts, "invalid output buffer payload\n");
			break;
		}
	}

	/*
	 * XXX: Calling the "ipts_send_feedback" function repeatedly seems to
	 * be what is causing touch to crash (found by sebanc, see the link
	 * below for the comment) on some models, especially on Surface Pro 4
	 * and Surface Book 1.
	 * The most desirable fix could be done by raising IPTS GuC priority.
	 * Until we find a better solution, use this workaround.
	 *
	 * The decision which devices have no_feedback enabled by default is
	 * made by the companion driver. If no companion driver was loaded,
	 * no_feedback is disabled and the default behaviour is used.
	 *
	 * Link to the comment where sebanc found this workaround:
	 * https://github.com/jakeday/linux-surface/issues/374#issuecomment-508234110
	 * (Touch and pen issue persists · Issue #374 · jakeday/linux-surface)
	 *
	 * Link to the usage from kitakar5525 who made this change:
	 * https://github.com/jakeday/linux-surface/issues/374#issuecomment-517289171
	 * (Touch and pen issue persists · Issue #374 · jakeday/linux-surface)
	 */
	if (fb_buf) {
		// A negative value means "decide by dmi table"
		if (ipts_modparams.no_feedback < 0) {
			if (ipts_get_quirks() & IPTS_QUIRK_NO_FEEDBACK)
				ipts_modparams.no_feedback = true;
			else
				ipts_modparams.no_feedback = false;
		}

		if (ipts_modparams.no_feedback)
			return 0;

		ret = ipts_send_feedback(ipts, parallel_idx, tr_id);
		if (ret)
			return ret;
	}

	return 0;
}

static int handle_output_buffers(struct ipts_info *ipts,
		int cur_idx, int end_idx)
{
	int max_num_of_buffers = ipts_get_num_of_parallel_buffers(ipts);

	do {
		cur_idx++; // cur_idx has last completed so starts with +1
		cur_idx %= max_num_of_buffers;
		handle_outputs(ipts, cur_idx);
	} while (cur_idx != end_idx);

	return 0;
}

int ipts_handle_processed_data(struct ipts_info *ipts)
{
	int ret = 0;
	int current_buffer_idx;
	int last_buffer_idx;

	current_buffer_idx = *ipts->last_submitted_id;
	last_buffer_idx = ipts->last_buffer_completed;

	if (current_buffer_idx == last_buffer_idx)
		return 0;

	ipts->last_buffer_completed = current_buffer_idx;
	handle_output_buffers(ipts, last_buffer_idx, current_buffer_idx);

	return ret;
}
