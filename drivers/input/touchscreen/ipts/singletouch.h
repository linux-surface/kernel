/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _IPTS_SINGLETOUCH_H_
#define _IPTS_SINGLETOUCH_H_

#include "context.h"
#include "protocol/touch.h"

void ipts_singletouch_parse_report(struct ipts_context *ipts,
		struct ipts_touch_data *data);
int ipts_singletouch_init(struct ipts_context *ipts);

#endif /* _IPTS_SINGLETOUCH_H_ */
