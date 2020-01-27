/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _IPTS_PROTOCOL_FEEDBACK_H_
#define _IPTS_PROTOCOL_FEEDBACK_H_

#include <linux/build_bug.h>
#include <linux/types.h>

enum ipts_feedback_type {
	IPTS_FEEDBACK_TYPE_NONE = 0,
	IPTS_FEEDBACK_TYPE_SOFT_RESET,
	IPTS_FEEDBACK_TYPE_GOTO_ARMED,
	IPTS_FEEDBACK_TYPE_GOTO_SENSING,
	IPTS_FEEDBACK_TYPE_GOTO_SLEEP,
	IPTS_FEEDBACK_TYPE_GOTO_DOZE,
	IPTS_FEEDBACK_TYPE_HARD_RESET,
	IPTS_FEEDBACK_TYPE_MAX
};

struct ipts_feedback {
	u32 type;
	u32 size;
	u32 transaction;
	u8 reserved[52];
	u8 data[];
} __packed;

static_assert(sizeof(struct ipts_feedback) == 64);

#endif /* _IPTS_PROTOCOL_FEEDBACK_H_ */
