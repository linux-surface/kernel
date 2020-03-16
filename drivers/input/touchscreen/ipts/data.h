/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _IPTS_DATA_H_
#define _IPTS_DATA_H_

#include "context.h"

int ipts_data_loop(void *data);
int ipts_data_init(struct ipts_context *ipts);
void ipts_data_free(struct ipts_context *ipts);

#endif /* _IPTS_DATA_H_ */
