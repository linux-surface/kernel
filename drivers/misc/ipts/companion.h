/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 * Intel Precise Touch & Stylus
 * Copyright (c) 2016 Intel Corporation
 *
 */

#ifndef _IPTS_COMPANION_H_
#define _IPTS_COMPANION_H_

#include <linux/firmware.h>
#include <linux/ipts-binary.h>

#include "ipts.h"

bool ipts_companion_available(void);
unsigned int ipts_get_quirks(void);

int ipts_request_firmware(const struct firmware **fw, const char *name,
		struct device *device);

int ipts_request_firmware_config(struct ipts_info *ipts,
		struct ipts_bin_fw_list **firmware_config);

#endif // _IPTS_COMPANION_H_
