/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 * Intel Precise Touch & Stylus
 * Copyright (c) 2016 Intel Corporation
 *
 */

#ifndef _IPTS_HID_H_
#define _IPTS_HID_H_

#include "ipts.h"

#define BUS_MEI 0x44

int ipts_hid_init(struct ipts_info *ipts);
void ipts_hid_release(struct ipts_info *ipts);
int ipts_handle_hid_data(struct ipts_info *ipts,
		struct touch_sensor_hid_ready_for_data_rsp_data *hid_rsp);

#endif // _IPTS_HID_H_
