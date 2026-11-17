/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2022-2023 Dorian Stoll
 *
 * Linux driver for Intel Precise Touch & Stylus
 */

#ifndef IPTS_HID_H
#define IPTS_HID_H

#include <linux/types.h>

#include "context.h"
#include "spec-device.h"

void ipts_hid_enable(struct ipts_context *ipts);
void ipts_hid_disable(struct ipts_context *ipts);

/**
 * ipts_hid_quiesce() - Disables HID callbacks and waits for running ones to return.
 * @ipts: The IPTS driver context.
 * @timeout_ms: How long to wait at most.
 *
 * Returns: 0 when no callback is running anymore, -ETIMEDOUT if one did not return.
 */
int ipts_hid_quiesce(struct ipts_context *ipts, unsigned int timeout_ms);

int ipts_hid_input_data(struct ipts_context *ipts, u32 buffer);

int ipts_hid_init(struct ipts_context *ipts, struct ipts_device_info info);
int ipts_hid_free(struct ipts_context *ipts);

#endif /* IPTS_HID_H */
