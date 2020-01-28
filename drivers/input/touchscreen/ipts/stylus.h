/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _IPTS_STYLUS_H_
#define _IPTS_STYLUS_H_

#include "context.h"
#include "protocol/touch.h"

void ipts_stylus_parse_report(struct ipts_context *ipts,
		struct ipts_touch_data *data);
int ipts_stylus_init(struct ipts_context *ipts);

#endif /* _IPTS_STYLUS_H_ */
