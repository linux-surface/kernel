// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/moduleparam.h>
#include <linux/types.h>

#include "params.h"

#define IPTS_PARM(NAME, TYPE, PERM) \
	module_param_named(NAME, ipts_params.NAME, TYPE, PERM)

#define IPTS_DESC(NAME, DESC) \
	MODULE_PARM_DESC(NAME, DESC)

struct ipts_modparams ipts_params = {
	.debug = false,
	.singletouch = false,
};

IPTS_PARM(debug, bool, 0400);
IPTS_DESC(debug,
	"Enable additional debugging in the IPTS driver (default: false)"
);

IPTS_PARM(singletouch, bool, 0400);
IPTS_DESC(singletouch,
	"Enables IPTS single touch mode (disables stylus) (default: false)"
);
