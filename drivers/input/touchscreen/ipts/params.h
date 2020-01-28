/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _IPTS_PARAMS_H_
#define _IPTS_PARAMS_H_

#include <linux/types.h>

struct ipts_modparams {
	bool debug;
	bool singletouch;
};

extern struct ipts_modparams ipts_params;

#endif /* _IPTS_PARAMS_H_ */
