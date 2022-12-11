// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Dorian Stoll
 *
 * Linux driver for Intel Precise Touch & Stylus
 */

#include <linux/hid.h>
#include <linux/types.h>

#include "context.h"

/**
 * ipts_eds2_get_descriptor() - Assembles the HID descriptor of the device.
 * @ipts: The IPTS driver context.
 * @desc_buffer: A pointer to the location where the address of the allocated buffer is stored.
 * @desc_size: A pointer to the location where the size of the allocated buffer is stored.
 *
 * Returns: 0 on success, <0 on error.
 */
int ipts_eds2_get_descriptor(struct ipts_context *ipts, u8 **desc_buffer, size_t *desc_size);

/**
 * ipts_eds2_raw_request() - Executes an output or feature report on the device.
 * @ipts: The IPTS driver context.
 * @buffer: The buffer containing the report.
 * @size: The size of the buffer.
 * @report_id: The HID report ID.
 * @report_type: Whether this report is an output or a feature report.
 * @request_type: Whether this report requests or sends data.
 *
 * Returns: 0 on success, <0 on error.
 */
int ipts_eds2_raw_request(struct ipts_context *ipts, u8 *buffer, size_t size, u8 report_id,
			  enum hid_report_type report_type, enum hid_class_request request_type);
