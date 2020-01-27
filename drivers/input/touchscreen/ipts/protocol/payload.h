/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _IPTS_PROTOCOL_PAYLOAD_H_
#define _IPTS_PROTOCOL_PAYLOAD_H_

#include <linux/build_bug.h>
#include <linux/types.h>

enum ipts_payload_frame_type {
	IPTS_PAYLOAD_FRAME_TYPE_STYLUS = 6,
	IPTS_PAYLOAD_FRAME_TYPE_TOUCH = 8,
};

enum ipts_report_type {
	IPTS_REPORT_TYPE_TOUCH_HEATMAP_DIM = 0x0403,
	IPTS_REPORT_TYPE_TOUCH_HEATMAP = 0x0425,
	IPTS_REPORT_TYPE_STYLUS_NO_TILT = 0x0410,
	IPTS_REPORT_TYPE_STYLUS_TILT = 0x0461,
	IPTS_REPORT_TYPE_STYLUS_TILT_SERIAL = 0x0460,
};

struct ipts_payload {
	u32 counter;
	u32 num_frames;
	u8 reserved[4];
	u8 data[];
} __packed;

struct ipts_payload_frame {
	u16 index;
	u16 type;
	u32 size;
	u8 reserved[8];
	u8 data[];
} __packed;

struct ipts_report {
	u16 type;
	u16 size;
	u8 data[];
} __packed;

static_assert(sizeof(struct ipts_payload) == 12);
static_assert(sizeof(struct ipts_payload_frame) == 16);
static_assert(sizeof(struct ipts_report) == 4);

#endif /* _IPTS_PROTOCOL_PAYLOAD_H_ */
