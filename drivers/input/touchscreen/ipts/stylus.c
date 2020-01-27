// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/input.h>
#include <linux/kernel.h>

#include "context.h"
#include "math.h"
#include "protocol/payload.h"
#include "protocol/stylus.h"

static void ipts_stylus_handle_stylus_data(struct ipts_context *ipts,
		struct ipts_stylus_report_data *data)
{
	u8 prox = data->mode & IPTS_STYLUS_REPORT_MODE_PROX;
	u8 touch = data->mode & IPTS_STYLUS_REPORT_MODE_TOUCH;
	u8 button = data->mode & IPTS_STYLUS_REPORT_MODE_BUTTON;
	u8 rubber = data->mode & IPTS_STYLUS_REPORT_MODE_ERASER;

	s32 tx = 0;
	s32 ty = 0;

	// avoid unnecessary computations
	// altitude is zero if stylus does not touch the screen
	if (data->altitude) {
		ipts_math_altitude_azimuth_to_tilt(data->altitude,
				data->azimuth, &tx, &ty);
	}

	input_report_key(ipts->stylus, BTN_TOUCH, touch);
	input_report_key(ipts->stylus, BTN_TOOL_PEN, prox && !rubber);
	input_report_key(ipts->stylus, BTN_TOOL_RUBBER, prox && rubber);
	input_report_key(ipts->stylus, BTN_STYLUS, button);

	input_report_abs(ipts->stylus, ABS_X, data->x);
	input_report_abs(ipts->stylus, ABS_Y, data->y);
	input_report_abs(ipts->stylus, ABS_PRESSURE, data->pressure);
	input_report_abs(ipts->stylus, ABS_MISC, data->timestamp);

	input_report_abs(ipts->stylus, ABS_TILT_X, tx);
	input_report_abs(ipts->stylus, ABS_TILT_Y, ty);

	input_sync(ipts->stylus);
}

static void ipts_stylus_handle_report_tilt_serial(struct ipts_context *ipts,
		struct ipts_report *report)
{
	int i;
	struct ipts_stylus_report_serial *stylus_report;
	struct ipts_stylus_report_data *data;

	stylus_report = (struct ipts_stylus_report_serial *)report->data;
	data = (struct ipts_stylus_report_data *)stylus_report->data;

	// TODO: Track serial number and support multiple styli

	for (i = 0; i < stylus_report->reports; i++)
		ipts_stylus_handle_stylus_data(ipts, &data[i]);
}

static void ipts_stylus_handle_report_tilt(struct ipts_context *ipts,
		struct ipts_report *report)
{
	int i;
	struct ipts_stylus_report *stylus_report;
	struct ipts_stylus_report_data *data;

	stylus_report = (struct ipts_stylus_report *)report->data;
	data = (struct ipts_stylus_report_data *)stylus_report->data;

	for (i = 0; i < stylus_report->reports; i++)
		ipts_stylus_handle_stylus_data(ipts, &data[i]);
}

static void ipts_stylus_handle_report_no_tilt(struct ipts_context *ipts,
		struct ipts_report *report)
{
	int i;
	struct ipts_stylus_report_serial *stylus_report;
	struct ipts_stylus_report_data_no_tilt *data;
	struct ipts_stylus_report_data new_data;

	stylus_report = (struct ipts_stylus_report_serial *)report->data;
	data = (struct ipts_stylus_report_data_no_tilt *)stylus_report->data;

	for (i = 0; i < stylus_report->reports; i++) {
		new_data.mode = data[i].mode;
		new_data.x = data[i].x;
		new_data.y = data[i].y;
		new_data.pressure = data[i].pressure * 4;
		new_data.altitude = 0;
		new_data.azimuth = 0;
		new_data.timestamp = 0;

		ipts_stylus_handle_stylus_data(ipts, &new_data);
	}
}

void ipts_stylus_handle_input(struct ipts_context *ipts,
		struct ipts_payload_frame *frame)
{
	int size;
	struct ipts_report *report;

	size = 0;

	while (size < frame->size) {
		report = (struct ipts_report *)&frame->data[size];
		size += sizeof(struct ipts_report) + report->size;

		switch (report->type) {
		case IPTS_REPORT_TYPE_STYLUS_NO_TILT:
			ipts_stylus_handle_report_no_tilt(ipts, report);
			break;
		case IPTS_REPORT_TYPE_STYLUS_TILT:
			ipts_stylus_handle_report_tilt(ipts, report);
			break;
		case IPTS_REPORT_TYPE_STYLUS_TILT_SERIAL:
			ipts_stylus_handle_report_tilt_serial(ipts, report);
			break;
		default:
			// ignored
			break;
		}
	}
}

int ipts_stylus_init(struct ipts_context *ipts)
{
	int ret;

	ipts->stylus = input_allocate_device();
	if (!ipts->stylus)
		return -ENOMEM;

	__set_bit(INPUT_PROP_DIRECT, ipts->stylus->propbit);
	__set_bit(INPUT_PROP_POINTER, ipts->stylus->propbit);

	input_set_abs_params(ipts->stylus, ABS_X, 0, 9600, 0, 0);
	input_abs_set_res(ipts->stylus, ABS_X, 34);
	input_set_abs_params(ipts->stylus, ABS_Y, 0, 7200, 0, 0);
	input_abs_set_res(ipts->stylus, ABS_Y, 38);
	input_set_abs_params(ipts->stylus, ABS_PRESSURE, 0, 4096, 0, 0);
	input_set_abs_params(ipts->stylus, ABS_TILT_X, -9000, 9000, 0, 0);
	input_abs_set_res(ipts->stylus, ABS_TILT_X, 5730);
	input_set_abs_params(ipts->stylus, ABS_TILT_Y, -9000, 9000, 0, 0);
	input_abs_set_res(ipts->stylus, ABS_TILT_Y, 5730);
	input_set_abs_params(ipts->stylus, ABS_MISC, 0, 65535, 0, 0);
	input_set_capability(ipts->stylus, EV_KEY, BTN_TOUCH);
	input_set_capability(ipts->stylus, EV_KEY, BTN_STYLUS);
	input_set_capability(ipts->stylus, EV_KEY, BTN_TOOL_PEN);
	input_set_capability(ipts->stylus, EV_KEY, BTN_TOOL_RUBBER);

	ipts->stylus->id.bustype = BUS_MEI;
	ipts->stylus->id.vendor = ipts->device_info.vendor_id;
	ipts->stylus->id.product = ipts->device_info.device_id;
	ipts->stylus->id.version = ipts->device_info.fw_rev;

	ipts->stylus->phys = "heci3";
	ipts->stylus->name = "IPTS Stylus";

	ret = input_register_device(ipts->stylus);
	if (ret) {
		dev_err(ipts->dev, "Cannot register input device: %s (%d)\n",
				ipts->stylus->name, ret);
		input_free_device(ipts->stylus);
		return ret;
	}

	return 0;
}

void ipts_stylus_free(struct ipts_context *ipts)
{
	if (!ipts->stylus)
		return;

	input_unregister_device(ipts->stylus);
}
