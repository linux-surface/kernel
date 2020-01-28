/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _IPTS_CONTROL_H_
#define _IPTS_CONTROL_H_

#include <linux/types.h>

#include "context.h"

int ipts_control_start(struct ipts_context *ipts);
void ipts_control_stop(struct ipts_context *ipts);
int ipts_control_restart(struct ipts_context *ipts);
int ipts_control_send(struct ipts_context *ipts,
		u32 cmd, void *data, u32 size);
int ipts_control_send_feedback(struct ipts_context *ipts,
		u32 buffer, u32 transaction);

#endif /* _IPTS_CONTROL_H_ */
