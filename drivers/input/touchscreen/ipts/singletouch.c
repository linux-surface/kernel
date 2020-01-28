// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/input.h>
#include <linux/input/mt.h>
#include <linux/kernel.h>

#include "context.h"
#include "protocol/enums.h"
#include "protocol/touch.h"

void ipts_singletouch_parse_report(struct ipts_context *ipts,
		struct ipts_touch_data *data)
{
	struct ipts_singletouch_report *report =
		(struct ipts_singletouch_report *)&data->data[1];

	input_report_key(ipts->singletouch, BTN_TOUCH, report->touch);
	input_report_abs(ipts->singletouch, ABS_X, report->x);
	input_report_abs(ipts->singletouch, ABS_Y, report->y);

	input_sync(ipts->singletouch);
}

int ipts_singletouch_init(struct ipts_context *ipts)
{
	int ret;

	ipts->singletouch = devm_input_allocate_device(ipts->dev);
	if (!ipts->singletouch)
		return -ENOMEM;

	__set_bit(INPUT_PROP_DIRECT, ipts->singletouch->propbit);

	input_set_capability(ipts->singletouch, EV_KEY, BTN_TOUCH);
	input_set_abs_params(ipts->singletouch, ABS_X, 0, 32767, 0, 0);
	input_abs_set_res(ipts->singletouch, ABS_X, 112);
	input_set_abs_params(ipts->singletouch, ABS_Y, 0, 32767, 0, 0);
	input_abs_set_res(ipts->singletouch, ABS_Y, 199);

	ipts->singletouch->id.bustype = BUS_MEI;
	ipts->singletouch->id.vendor = ipts->device_info.vendor_id;
	ipts->singletouch->id.product = ipts->device_info.device_id;
	ipts->singletouch->id.version = ipts->device_info.fw_rev;

	ipts->singletouch->phys = "heci3";
	ipts->singletouch->name = "Intel Precise Touchscreen (Singletouch)";

	ret = input_register_device(ipts->singletouch);
	if (ret) {
		dev_err(ipts->dev, "Failed to register touch device: %d\n",
				ret);
		return ret;
	}

	return 0;
}
