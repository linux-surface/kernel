/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _IPTS_DEVICES_H_
#define _IPTS_DEVICES_H_

#include <linux/types.h>

/*
 * These names describe the different iterations of the IPTS stylus protocol.
 *
 * IPTS_STYLUS_PROTOCOL_GEN1 can be found on devices that don't have
 * support for tilt, and only 1024 pressure levels. (Using NTRIG digitizers)
 *
 * IPTS_STYLUS_PROTOCOL_GEN2 can be found on devices that support tilting
 * the stylus, with 4096 levels of pressure. (Using MS digitizers)
 *
 * New generations have to be added as they are discovered.
 */
enum ipts_stylus_protocol {
	IPTS_STYLUS_PROTOCOL_GEN1,
	IPTS_STYLUS_PROTOCOL_GEN2
};

struct ipts_device_config {
	u32 vendor_id;
	u32 device_id;
	u32 max_stylus_pressure;
	enum ipts_stylus_protocol stylus_protocol;
};

struct ipts_device_config ipts_devices_get_config(u32 vendor, u32 device);

#endif /* _IPTS_DEVICES_H_ */
