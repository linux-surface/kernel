/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _IPTS_UAPI_H_
#define _IPTS_UAPI_H_

#include "context.h"

int ipts_uapi_init(struct ipts_context *ipts);
void ipts_uapi_free(struct ipts_context *ipts);

#endif /* _IPTS_UAPI_H_ */
