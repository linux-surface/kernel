/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _IPTS_CONTEXT_H_
#define _IPTS_CONTEXT_H_

#include <linux/kthread.h>
#include <linux/input.h>
#include <linux/mei_cl_bus.h>
#include <linux/types.h>

#include "protocol/commands.h"
#include "protocol/responses.h"

/* HACK: Workaround for DKMS build without BUS_MEI patch */
#ifndef BUS_MEI
#define BUS_MEI 0x44
#endif

/* IPTS driver states */
enum ipts_host_status {
	IPTS_HOST_STATUS_NONE,
	IPTS_HOST_STATUS_INIT,
	IPTS_HOST_STATUS_RESOURCE_READY,
	IPTS_HOST_STATUS_STARTED,
	IPTS_HOST_STATUS_STOPPING,
	IPTS_HOST_STATUS_RESTARTING
};

struct ipts_buffer_info {
	u8 *address;
	dma_addr_t dma_address;
};

struct ipts_context {
	struct mei_cl_device *client_dev;
	struct device *dev;
	struct ipts_device_info device_info;

	enum ipts_host_status status;
	enum ipts_sensor_mode mode;

	struct ipts_buffer_info data[16];
	struct ipts_buffer_info feedback[16];
	struct ipts_buffer_info doorbell;

	/*
	 * These buffers are not actually used by anything, but they need
	 * to be allocated and passed to the ME to get proper functionality.
	 */
	struct ipts_buffer_info workqueue;
	struct ipts_buffer_info host2me;

	struct task_struct *receiver_loop;
	struct task_struct *data_loop;

	struct input_dev *stylus;
	struct input_dev *singletouch;
};

#endif /* _IPTS_CONTEXT_H_ */
