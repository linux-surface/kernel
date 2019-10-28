/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 * Intel Precise Touch & Stylus
 * Copyright (c) 2016 Intel Corporation
 *
 */

#ifndef _IPTS_PARAMS_H_
#define _IPTS_PARAMS_H_

#include <linux/types.h>

struct ipts_params {
	bool ignore_fw_fallback;
	bool ignore_config_fallback;
	bool ignore_companion;
	int no_feedback;

	bool debug;
	bool debug_thread;
};

extern struct ipts_params ipts_modparams;

#endif // _IPTS_PARAMS_H_
