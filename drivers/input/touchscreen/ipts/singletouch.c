// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/input.h>
#include <linux/kernel.h>

#include "context.h"
#include "protocol/data.h"
#include "protocol/singletouch.h"

void ipts_singletouch_handle_input(struct ipts_context *ipts,
		struct ipts_data *data)
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

	ipts->singletouch = input_allocate_device();
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
	ipts->singletouch->name = "IPTS Singletouch";

	ret = input_register_device(ipts->singletouch);
	if (ret) {
		dev_err(ipts->dev, "Cannot register input device: %s (%d)\n",
				ipts->singletouch->name, ret);
		input_free_device(ipts->singletouch);
		return ret;
	}

	return 0;
}

void ipts_singletouch_free(struct ipts_context *ipts)
{
	if (!ipts->singletouch)
		return;

	input_unregister_device(ipts->singletouch);
}
