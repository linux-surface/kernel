/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _IPTS_RESOURCES_H_
#define _IPTS_RESOURCES_H_

#include "context.h"

int ipts_resources_init(struct ipts_context *ipts);
void ipts_resources_free(struct ipts_context *ipts);

#endif /* _IPTS_RESOURCES_H_ */
