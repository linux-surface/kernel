// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 * Intel Precise Touch & Stylus
 * Copyright (c) 2016 Intel Corporation
 *
 */

#include <linux/device.h>
#include <stdarg.h>

#include "ipts.h"
#include "params.h"

static void ipts_printk(const char *level, const struct device *dev,
		struct va_format *vaf)
{
	if (dev) {
		dev_printk_emit(level[1] - '0', dev, "%s %s: %pV",
			dev_driver_string(dev), dev_name(dev), vaf);
	} else {
		// checkpatch wants this to be prefixed with KERN_*, but
		// since the level is passed as a parameter, ignore it
		printk("%s(NULL device *): %pV", level, vaf);
	}
}

void ipts_info(struct ipts_info *ipts, const char *fmt, ...)
{
	va_list args;
	struct va_format vaf;

	if (!ipts_modparams.debug)
		return;

	va_start(args, fmt);

	vaf.fmt = fmt;
	vaf.va = &args;

	ipts_printk(KERN_INFO, &ipts->cldev->dev, &vaf);

	va_end(args);
}

void ipts_dbg(struct ipts_info *ipts, const char *fmt, ...)
{
	va_list args;
	struct va_format vaf;

	if (!ipts_modparams.debug)
		return;

	va_start(args, fmt);

	vaf.fmt = fmt;
	vaf.va = &args;

	ipts_printk(KERN_DEBUG, &ipts->cldev->dev, &vaf);

	va_end(args);
}
