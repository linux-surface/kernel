/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _IPTS_PROTOCOL_RESPONSES_H_
#define _IPTS_PROTOCOL_RESPONSES_H_

#include <linux/build_bug.h>
#include <linux/types.h>

#include "enums.h"

struct ipts_device_info {
	u16 vendor_id;
	u16 device_id;
	u32 hw_rev;
	u32 fw_rev;

	/* Required size of one touch data buffer */
	u32 frame_size;

	/* Required size of one feedback buffer */
	u32 feedback_size;
	u8 reserved[24];
} __packed;

/*
 * Responses are sent from the ME to the host, reacting to a command.
 */
struct ipts_response {
	u32 code;
	u32 status;
	union {
		struct ipts_device_info device_info;
		u8 reserved[80];
	} data;
} __packed;

static_assert(sizeof(struct ipts_device_info) == 44);
static_assert(sizeof(struct ipts_response) == 88);

#endif /* _IPTS_PROTOCOL_RESPONSES_H_ */
