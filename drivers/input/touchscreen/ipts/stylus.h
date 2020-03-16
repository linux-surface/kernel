/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _IPTS_STYLUS_H_
#define _IPTS_STYLUS_H_

#include "context.h"
#include "protocol/payload.h"

void ipts_stylus_handle_input(struct ipts_context *ipts,
		struct ipts_payload_frame *frame);
int ipts_stylus_init(struct ipts_context *ipts);
void ipts_stylus_free(struct ipts_context *ipts);

#endif /* _IPTS_STYLUS_H_ */
