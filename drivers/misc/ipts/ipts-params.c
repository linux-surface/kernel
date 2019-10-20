#include <linux/moduleparam.h>

#include "ipts-params.h"

struct ipts_params ipts_modparams = {
	.ignore_fw_fallback = false,
	.ignore_config_fallback = false,
	.ignore_companion = false,
	.no_feedback = -1,
};

module_param_named(ignore_fw_fallback, ipts_modparams.ignore_fw_fallback, bool, 0400);
MODULE_PARM_DESC(ignore_fw_fallback, "Don't use the IPTS firmware fallback path");

module_param_named(ignore_config_fallback, ipts_modparams.ignore_config_fallback, bool, 0400);
MODULE_PARM_DESC(ignore_config_fallback, "Don't try to load the IPTS firmware config from a file");

module_param_named(ignore_companion, ipts_modparams.ignore_companion, bool, 0400);
MODULE_PARM_DESC(ignore_companion, "Don't use a companion driver to load firmware");

module_param_named(no_feedback, ipts_modparams.no_feedback, int, 0644);
MODULE_PARM_DESC(no_feedback, "Disable sending feedback in order to work around the issue that IPTS "
	"stops working after some amount of use. "
	"-1=auto (true if your model is SB1/SP4, false if another model), "
	"0=false, 1=true, (default: -1)");
