// SPDX-License-Identifier: GPL-2.0-or-later

#include "context.h"
#include "protocol/data.h"
#include "singletouch.h"

/*
 * IPTS on surface gen7 appears to make heavy use of HID reports, unlike
 * previous generations. This file can be used to implement handling for
 * them in the future, seperated from the actual singletouch implementation.
 */

void ipts_hid_handle_input(struct ipts_context *ipts, struct ipts_data *data)
{
	// Make sure that we only handle singletouch inputs
	// 40 is the report id of the singletouch device in the generic
	// IPTS HID descriptor.
	if (data->data[0] != 0x40)
		return;

	ipts_singletouch_handle_input(ipts, data);
}

int ipts_hid_init(struct ipts_context *ipts)
{
	int ret;

	ret = ipts_singletouch_init(ipts);
	if (ret)
		return ret;

	return 0;
}

void ipts_hid_free(struct ipts_context *ipts)
{
	ipts_singletouch_free(ipts);
}
