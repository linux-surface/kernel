/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _IPTS_PROTOCOL_SINGLETOUCH_H_
#define _IPTS_PROTOCOL_SINGLETOUCH_H_

#include <linux/build_bug.h>
#include <linux/types.h>

struct ipts_singletouch_report {
	u8 touch;
	u16 x;
	u16 y;
} __packed;

static_assert(sizeof(struct ipts_singletouch_report) == 5);

#endif /* _IPTS_PROTOCOL_SINGLETOUCH_H_ */
