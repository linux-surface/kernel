/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 * Intel Precise Touch & Stylus
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2019 Dorian Stoll
 *
 */

#ifndef IPTS_COMPANION_H
#define IPTS_COMPANION_H

#include <linux/firmware.h>
#include <linux/ipts-binary.h>

struct ipts_companion {
	unsigned int (*get_quirks)(struct ipts_companion *companion);
	int (*firmware_request)(struct ipts_companion *companion,
		const struct firmware **fw,
		const char *name, struct device *device);

	struct ipts_bin_fw_info **firmware_config;
	void *data;
	const char *name;
};

int ipts_add_companion(struct ipts_companion *companion);
int ipts_remove_companion(struct ipts_companion *companion);

#endif // IPTS_COMPANION_H
