/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 * Intel Precise Touch & Stylus
 * Copyright (c) 2016 Intel Corporation
 *
 */

#ifndef _IPTS_KERNEL_H_
#define _IPTS_KERNEL_H_

#include "ipts.h"

int ipts_init_kernels(struct ipts_info *ipts);
void ipts_release_kernels(struct ipts_info *ipts);

#endif // _IPTS_KERNEL_H_
