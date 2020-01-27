/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _IPTS_HID_H_
#define _IPTS_HID_H_

#include "context.h"

enum ipts_report_type {
	IPTS_REPORT_TYPE_STYLUS,
	IPTS_REPORT_TYPE_SINGLETOUCH,
	IPTS_REPORT_TYPE_MAX
};

int ipts_hid_init(struct ipts_context *ipts);
int ipts_hid_loop(void *data);

#endif /* _IPTS_HID_H_ */
