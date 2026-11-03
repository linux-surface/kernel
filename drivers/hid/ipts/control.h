/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2020-2023 Dorian Stoll
 *
 * Linux driver for Intel Precise Touch & Stylus
 */

#ifndef IPTS_CONTROL_H
#define IPTS_CONTROL_H

#include <linux/types.h>

#include "context.h"
#include "mei.h"
#include "receiver.h"
#include "spec-data.h"
#include "spec-device.h"

/**
 * ipts_control_request_flush() - Stop the data flow.
 * @ipts: The IPTS driver context.
 *
 * Runs the command to stop the data flow on the device.
 * All outstanding data needs to be acknowledged using feedback before the command will return.
 *
 * Returns: 0 on success, <0 on error.
 */
int ipts_control_request_flush(struct ipts_context *ipts);

/**
 * ipts_control_wait_flush() - Wait until data flow has been stopped.
 * @ipts: The IPTS driver context.
 *
 * Returns: 0 on success, <0 on error.
 */
int ipts_control_wait_flush(struct ipts_context *ipts);

/**
 * ipts_control_wait_flush() - Notify the device that the driver can receive new data.
 * @ipts: The IPTS driver context.
 *
 * Returns: 0 on success, <0 on error.
 */
int ipts_control_request_data(struct ipts_context *ipts);

/**
 * ipts_control_wait_data() - Wait until new data is available.
 * @ipts: The IPTS driver context.
 * @block: Whether to block execution until data is available.
 *
 * In poll mode, this function will never return while the data flow is active. Instead,
 * the poll will be incremented when new data is available.
 *
 * Returns: 0 on success, <0 on error, -EAGAIN if no data is available.
 */
int ipts_control_wait_data(struct ipts_context *ipts, bool block);

/**
 * ipts_control_send_feedback() - Submits a feedback buffer to the device.
 * @ipts: The IPTS driver context.
 * @buffer: The ID of the buffer containing feedback data.
 *
 * Returns: 0 on success, <0 on error.
 */
int ipts_control_send_feedback(struct ipts_context *ipts, u32 buffer);

/**
 * ipts_control_hid2me_feedback() - Sends HID2ME feedback, a special type of feedback.
 * @ipts: The IPTS driver context.
 * @cmd: The command that will be run on the device.
 * @type: The type of the payload that is sent to the device.
 * @data: The payload of the feedback command.
 * @size: The size of the payload.
 *
 * HID2ME feedback is a special type of feedback, because it allows interfacing with
 * the HID API of the device at any moment, without requiring a buffer that has to
 * be acknowledged.
 *
 * Returns: 0 on success, <0 on error.
 */
int ipts_control_hid2me_feedback(struct ipts_context *ipts, enum ipts_feedback_cmd_type cmd,
				 enum ipts_feedback_data_type type, void *data, size_t size);

/**
 * ipts_control_refill_buffer() - Acknowledges that data in a buffer has been processed.
 * @ipts: The IPTS driver context.
 * @buffer: The buffer that has been processed and can be refilled.
 *
 * Returns: 0 on success, <0 on error.
 */
static inline int ipts_control_refill_buffer(struct ipts_context *ipts, u32 buffer)
{
	/*
	 * IPTS expects structured data in the feedback buffer matching the buffer that will be
	 * refilled. We don't know what that data looks like, so we just keep the buffer empty.
	 * This results in an INVALID_PARAMS error, but the buffer gets refilled without an issue.
	 * Sending a minimal structure with the buffer ID fixes the error, but breaks refilling
	 * the buffers on some devices.
	 */

	return ipts_control_send_feedback(ipts, buffer);
}

/*
 * The longest ipts_control_start() takes on a restart. Only EDS1 devices restart. They send
 * three commands that wait for their reply (GET_DEVICE_INFO, SET_MODE and SET_MEM_WINDOW) and
 * READY_FOR_DATA, which is only sent. GET_DESCRIPTOR is sent only to newer devices, since the
 * EDS1 HID descriptor is built into the driver, and the rest of a start sends no command. The
 * bound still counts four replies; the fourth is margin.
 */
#define IPTS_CONTROL_START_TIMEOUT_MS (4 * IPTS_RECEIVER_CMD_MS + IPTS_MEI_SEND_TIMEOUT_MS)

/*
 * How long stopping waits for running HID callbacks. The longest of them, a GET_FEATURE
 * request, is released at once by ipts_hid_quiesce().
 */
#define IPTS_HID_QUIESCE_TIMEOUT_MS 12000

/*
 * The longest a stop takes: the wait for running HID callbacks, then the stop of the receiver
 * thread.
 */
#define IPTS_CONTROL_STOP_TIMEOUT_MS (IPTS_HID_QUIESCE_TIMEOUT_MS + IPTS_RECEIVER_STOP_TIMEOUT_MS)

/**
 * ipts_control_start() - Initialized the device and starts the data flow.
 * @ipts: The IPTS driver context.
 *
 * Returns: 0 on success, <0 on error.
 */
int ipts_control_start(struct ipts_context *ipts);

/**
 * ipts_control_stop() - Stops the data flow and resets the device.
 * @ipts: The IPTS driver context.
 *
 * Returns: 0 if the receiver thread stopped (the DMA buffers are leaked if the device did not
 * confirm the stop, or a HID callback outlived the wait for it), -ETIMEDOUT if it is still
 * running (the HID device is destroyed, the buffers are kept), -EBUSY if a HID callback did
 * not return (everything is kept), <0 on other errors.
 */
int ipts_control_stop(struct ipts_context *ipts);

/**
 * ipts_control_restart() - Schedules a stop and start of the device.
 * @ipts: The IPTS driver context.
 *
 * Returns: 0 if the restart was scheduled, <0 on error.
 */
int ipts_control_restart(struct ipts_context *ipts);

/**
 * ipts_control_cancel_restart() - Cancels a restart that is queued but not running yet.
 * @ipts: The IPTS driver context.
 */
void ipts_control_cancel_restart(struct ipts_context *ipts);

/**
 * ipts_control_init() - Initializes the lock and the work item of the context.
 * @ipts: The IPTS driver context.
 */
void ipts_control_init(struct ipts_context *ipts);

#endif /* IPTS_CONTROL_H */
