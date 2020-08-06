/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _IPTS_CONTEXT_H_
#define _IPTS_CONTEXT_H_

#include <linux/kthread.h>
#include <linux/mei_cl_bus.h>
#include <linux/miscdevice.h>
#include <linux/types.h>

#include "protocol.h"

/*
 * enum ipts_host_states - States of the IPTS driver
 *
 * IPTS_HOST_STATUS_STOPPED:
 *
 *   The driver was either shut down or encountered a fatal error, causing
 *   it to disable itself. In this state no messages from the ME will be read,
 *   and no data can be read by userspace.
 *
 * IPTS_HOST_STATUS_STARTING:
 *
 *   The driver is currently going through the initialization sequence.
 *   ME messages will be read, but no data can be read by userspace.
 *
 * IPTS_HOST_STATUS_STARTED:
 *
 *   The driver completely initialized the device and receives data from
 *   it. Userspace can now read data.
 *
 * IPTS_HOST_STATUS_RESTARTING:
 *
 *   A sensor error triggered a restart. Restarting IPTS means to stash all
 *   current operations using QUIESCE_IO, and then rerun the initialization
 *   sequence after the command returned. Since the same command is also used
 *   during shutdown, this mode tells the response handler for QUIESCE_IO if
 *   it should start re-initialization.
 */
enum ipts_host_status {
	IPTS_HOST_STATUS_STOPPED,
	IPTS_HOST_STATUS_STARTING,
	IPTS_HOST_STATUS_STARTED,
	IPTS_HOST_STATUS_RESTARTING
};

/*
 * struct ipts_buffer_info - Buffer for passing data between ME and host.
 *
 * @address: The virtual kernelspace address for the host to access the buffer.
 * @dma_address: The physical address for the ME to access the buffer.
 */
struct ipts_buffer_info {
	u8 *address;
	dma_addr_t dma_address;
};

/*
 * struct ipts_uapi - Context for the userspace interface
 *
 * @device: The character device that IPTS data can be read from.
 * @doorbell_thread: Polls the doorbell value and signals changes to userspace.
 * @doorbell: The last transaction that was passed to userspace.
 * @active: Whether a client has activated and locked the data stream.
 */
struct ipts_uapi {
	struct miscdevice device;
	struct task_struct *db_thread;

	u32 doorbell;
	bool active;
};

/*
 * struct ipts_context - Context for the IPTS driver
 *
 * @cldev: The MEI client device for IPTS.
 * @dev: The Linux driver model device, used for logging.
 * @device_info: Information about the device we are connected to.
 *
 * @status: Current state of the driver.
 * @uapi: The context for the userspace interface.
 *
 * @data: The IPTS data buffers. They get filled with touch data that is
 *        forwarded to userspace and parsed into input events.
 *
 * @doorbell: An unsigned 32-bit integer that will be incremented after one
 *            data buffer has been filled up. Always corresponds to the data
 *            buffer that will be filled *next*.
 *
 * The following buffers are a leftover from when IPTS used binary firmware
 * with GuC submission. They are not used by the host but they need to be
 * allocated to ensure proper operation.
 *
 * @feedback: Buffers that contain payload data for the FEEDBACK command.
 *            The command works with an empty buffer, so these are not used.
 *
 * @workqueue: Buffer that was used to synchronize the ME with the firmware
 *             running on the GuC. Just like the GuC, this buffer is not
 *             used anymore.
 *
 * @host2me: A special channel for sending feedback that is not linked to one
 *           of the data buffers. It is identified by using IPTS_BUFFERS as
 *           the buffer index, instead of 0 < n < IPTS_BUFFERS. In theory it
 *           allows for advanced interaction with the sensor, but these
 *           usages were never used or documented by intel, therefor it
 *           cannot be used.
 */
struct ipts_context {
	struct mei_cl_device *cldev;
	struct device *dev;
	struct ipts_device_info device_info;

	enum ipts_host_status status;
	struct ipts_uapi uapi;

	struct ipts_buffer_info data[IPTS_BUFFERS];
	struct ipts_buffer_info doorbell;

	struct ipts_buffer_info feedback[IPTS_BUFFERS];
	struct ipts_buffer_info workqueue;
	struct ipts_buffer_info host2me;
};

#endif /* _IPTS_CONTEXT_H_ */
