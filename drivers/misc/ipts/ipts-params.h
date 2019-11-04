#ifndef _IPTS_PARAMS_H_
#define _IPTS_PARAMS_H_

#include <linux/types.h>

struct ipts_params {
	bool ignore_fw_fallback;
	bool ignore_config_fallback;
	bool ignore_companion;
	int no_feedback;
};

extern struct ipts_params ipts_modparams;

#endif // _IPTS_PARAMS_H_
