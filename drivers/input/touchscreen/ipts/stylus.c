// SPDX-License-Identifier: GPL-2.0-or-later

#include <asm/fpu/api.h>
#include <linux/input.h>
#include <linux/kernel.h>

#include "context.h"
#include "devices.h"
#include "math.h"
#include "protocol/enums.h"
#include "protocol/touch.h"

static void ipts_stylus_handle_report(struct ipts_context *ipts,
		struct ipts_stylus_report *report)
{
	u16 tool;
	u8 prox = report->mode & IPTS_STYLUS_REPORT_MODE_PROXIMITY;
	u8 touch = report->mode & IPTS_STYLUS_REPORT_MODE_TOUCH;
	u8 button = report->mode & IPTS_STYLUS_REPORT_MODE_BUTTON;
	u8 rubber = report->mode & IPTS_STYLUS_REPORT_MODE_RUBBER;

	s32 tx = 0;
	s32 ty = 0;

	// avoid unnecessary computations
	// altitude is zero if stylus does not touch the screen
	if (report->altitude) {
		ipts_math_altitude_azimuth_to_tilt(report->altitude,
				report->azimuth, &tx, &ty);
	}

	if (prox && rubber)
		tool = BTN_TOOL_RUBBER;
	else
		tool = BTN_TOOL_PEN;

	// Fake proximity out to switch tools
	if (ipts->stylus_tool != tool) {
		input_report_key(ipts->stylus, ipts->stylus_tool, 0);
		input_sync(ipts->stylus);
		ipts->stylus_tool = tool;
	}

	input_report_key(ipts->stylus, BTN_TOUCH, touch);
	input_report_key(ipts->stylus, ipts->stylus_tool, prox);
	input_report_key(ipts->stylus, BTN_STYLUS, button);

	input_report_abs(ipts->stylus, ABS_X, report->x);
	input_report_abs(ipts->stylus, ABS_Y, report->y);
	input_report_abs(ipts->stylus, ABS_PRESSURE, report->pressure);
	input_report_abs(ipts->stylus, ABS_MISC, report->timestamp);

	input_report_abs(ipts->stylus, ABS_TILT_X, tx);
	input_report_abs(ipts->stylus, ABS_TILT_Y, ty);

	input_sync(ipts->stylus);
}

static void ipts_stylus_parse_report_gen1(struct ipts_context *ipts,
		struct ipts_touch_data *data)
{
	u8 count, i;
	struct ipts_stylus_report report;
	struct ipts_stylus_report_gen1 *reports;

	count = data->data[32];
	reports = (struct ipts_stylus_report_gen1 *)&data->data[44];

	for (i = 0; i < count; i++) {
		report.mode = reports[i].mode;
		report.x = reports[i].x;
		report.y = reports[i].y;
		report.pressure = reports[i].pressure;

		// The gen1 protocol doesn't support tilting the stylus
		report.altitude = 0;
		report.azimuth = 0;

		// Use the buffer ID to emulate a timestamp
		report.timestamp = data->buffer;

		ipts_stylus_handle_report(ipts, &report);
	}
}

static void ipts_stylus_parse_report_gen2(struct ipts_context *ipts,
		struct ipts_touch_data *data)
{
	u8 count, i;
	struct ipts_stylus_report *reports;

	count = data->data[32];
	reports = (struct ipts_stylus_report *)&data->data[40];

	for (i = 0; i < count; i++)
		ipts_stylus_handle_report(ipts, &reports[i]);
}

void ipts_stylus_parse_report(struct ipts_context *ipts,
		struct ipts_touch_data *data)
{
	switch (ipts->device_cfg.stylus_protocol) {
	case IPTS_STYLUS_PROTOCOL_GEN1:
		ipts_stylus_parse_report_gen1(ipts, data);
		break;
	case IPTS_STYLUS_PROTOCOL_GEN2:
		ipts_stylus_parse_report_gen2(ipts, data);
		break;
	}
}

int ipts_stylus_init(struct ipts_context *ipts)
{
	int ret;
	u16 pressure;

	ipts->stylus = devm_input_allocate_device(ipts->dev);
	if (!ipts->stylus)
		return -ENOMEM;

	pressure = ipts->device_cfg.max_stylus_pressure;

	ipts->stylus_tool = BTN_TOOL_PEN;

	__set_bit(INPUT_PROP_DIRECT, ipts->stylus->propbit);
	__set_bit(INPUT_PROP_POINTER, ipts->stylus->propbit);

	input_set_abs_params(ipts->stylus, ABS_X, 0, 9600, 0, 0);
	input_abs_set_res(ipts->stylus, ABS_X, 34);
	input_set_abs_params(ipts->stylus, ABS_Y, 0, 7200, 0, 0);
	input_abs_set_res(ipts->stylus, ABS_Y, 38);
	input_set_abs_params(ipts->stylus, ABS_PRESSURE, 0, pressure, 0, 0);
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
	ipts->stylus->name = "Intel Precise Stylus";

	ret = input_register_device(ipts->stylus);
	if (ret) {
		dev_err(ipts->dev, "Failed to register stylus device: %d\n",
				ret);
		return ret;
	}

	return 0;
}
