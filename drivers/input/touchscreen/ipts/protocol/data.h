/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _IPTS_PROTOCOL_DATA_H_
#define _IPTS_PROTOCOL_DATA_H_

#include <linux/build_bug.h>
#include <linux/types.h>

enum ipts_data_type {
	IPTS_DATA_TYPE_PAYLOAD = 0,
	IPTS_DATA_TYPE_ERROR,
	IPTS_DATA_TYPE_VENDOR_DATA,
	IPTS_DATA_TYPE_HID_REPORT,
	IPTS_DATA_TYPE_GET_FEATURES,
	IPTS_DATA_TYPE_MAX
};

struct ipts_data {
	u32 type;
	u32 size;
	u32 buffer;
	u8 reserved1[20];
	u8 transaction;
	u8 reserved2[31];
	u8 data[];
} __packed;

static_assert(sizeof(struct ipts_data) == 64);

#endif /* _IPTS_PROTOCOL_DATA_H_ */
