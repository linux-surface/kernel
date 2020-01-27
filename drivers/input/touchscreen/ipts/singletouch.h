/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _IPTS_SINGLETOUCH_H_
#define _IPTS_SINGLETOUCH_H_

#include "context.h"
#include "protocol/data.h"

void ipts_singletouch_handle_input(struct ipts_context *ipts,
		struct ipts_data *data);
int ipts_singletouch_init(struct ipts_context *ipts);
void ipts_singletouch_free(struct ipts_context *ipts);

#endif /* _IPTS_SINGLETOUCH_H_ */
