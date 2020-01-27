// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/kernel.h>
#include <linux/types.h>

#include "devices.h"

static const struct ipts_device_config ipts_devices[] = {
	{
		.vendor_id = 0x1B96,
		.device_id = 0x006A,
		.max_stylus_pressure = 1024,
		.stylus_protocol = IPTS_STYLUS_PROTOCOL_GEN1,
	},
	{
		.vendor_id = 0x1B96,
		.device_id = 0x005e,
		.max_stylus_pressure = 1024,
		.stylus_protocol = IPTS_STYLUS_PROTOCOL_GEN1,
	},
};

struct ipts_device_config ipts_devices_get_config(u32 vendor, u32 device)
{
	int i;
	struct ipts_device_config cfg;

	for (i = 0; i < ARRAY_SIZE(ipts_devices); i++) {
		cfg = ipts_devices[i];

		if (cfg.vendor_id != vendor)
			continue;
		if (cfg.device_id != device)
			continue;

		return cfg;
	}

	// No device was found, so return a default config
	cfg.vendor_id = vendor;
	cfg.device_id = device;
	cfg.max_stylus_pressure = 4096;
	cfg.stylus_protocol = IPTS_STYLUS_PROTOCOL_GEN2;

	return cfg;
}
