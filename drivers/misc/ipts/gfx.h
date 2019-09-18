/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 * Intel Precise Touch & Stylus
 * Copyright (c) 2016 Intel Corporation
 *
 */

#ifndef _IPTS_GFX_H_
#define _IPTS_GFX_H_

#include <linux/ipts-gfx.h>

#include "ipts.h"

int ipts_open_gpu(struct ipts_info *ipts);
void ipts_close_gpu(struct ipts_info *ipts);

struct ipts_mapbuffer *ipts_map_buffer(struct ipts_info *ipts,
		u32 size, u32 flags);

void ipts_unmap_buffer(struct ipts_info *ipts,
		struct ipts_mapbuffer *buf);

#endif // _IPTS_GFX_H_
