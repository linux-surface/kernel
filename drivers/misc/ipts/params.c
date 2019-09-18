// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 * Intel Precise Touch & Stylus
 * Copyright (c) 2016 Intel Corporation
 *
 */

#include <linux/moduleparam.h>

#include "params.h"

#define IPTS_PARAM(NAME, TYPE, PERM, DESC)				\
	module_param_named(NAME, ipts_modparams.NAME, TYPE, PERM);	\
	MODULE_PARM_DESC(NAME, DESC)

struct ipts_params ipts_modparams = {
	.ignore_fw_fallback = false,
	.ignore_config_fallback = false,
	.ignore_companion = false,
	.no_feedback = -1,

	.debug = false,
	.debug_thread = false,
};

IPTS_PARAM(ignore_fw_fallback, bool, 0400,
	"Don't use the IPTS firmware fallback path. (default: false)"
);
IPTS_PARAM(ignore_config_fallback, bool, 0400,
	"Don't try to load the IPTS firmware config from a file. (default: false)"
);
IPTS_PARAM(ignore_companion, bool, 0400,
	"Don't use a companion driver to load firmware. (default: false)"
);
IPTS_PARAM(no_feedback, int, 0644,
	"Disable sending feedback to ME (can prevent crashes on Skylake). (-1=auto [default], 0=false, 1=true)"
);

IPTS_PARAM(debug, bool, 0400,
	"Enable IPTS debugging output. (default: false)"
);
IPTS_PARAM(debug_thread, bool, 0400,
	"Periodically print the ME status into the kernel log. (default: false)"
);

