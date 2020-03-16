/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _IPTS_HID_H_
#define _IPTS_HID_H_

#include "context.h"
#include "protocol/data.h"

int ipts_hid_handle_input(struct ipts_context *ipts, struct ipts_data *data);
int ipts_hid_init(struct ipts_context *ipts);
void ipts_hid_free(struct ipts_context *ipts);

#endif /* _IPTS_HID_H_ */
