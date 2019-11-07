/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 * Intel Precise Touch & Stylus
 * Copyright (c) 2016 Intel Corporation
 *
 */

#ifndef _IPTS_STATE_H_
#define _IPTS_STATE_H_

// IPTS driver states
enum ipts_state {
	IPTS_STA_NONE,
	IPTS_STA_INIT,
	IPTS_STA_RESOURCE_READY,
	IPTS_STA_HID_STARTED,
	IPTS_STA_RAW_DATA_STARTED,
	IPTS_STA_STOPPING
};

#endif // _IPTS_STATE_H_
