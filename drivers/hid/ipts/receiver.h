/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2020-2023 Dorian Stoll
 *
 * Linux driver for Intel Precise Touch & Stylus
 */

#ifndef IPTS_RECEIVER_H
#define IPTS_RECEIVER_H

#include "cmd.h"
#include "context.h"
#include "mei.h"

/*
 * How long the end of a stop waits for the device to confirm QUIESCE_IO.
 */
#define IPTS_RECEIVER_STOP_CONFIRM_MS 3000

/*
 * The longest one command (a send and its reply) can take.
 */
#define IPTS_RECEIVER_CMD_MS (IPTS_MEI_SEND_TIMEOUT_MS + IPTS_CMD_DEFAULT_TIMEOUT)

/*
 * How long a stop waits for the receiver thread to return: the sum of the bounds of what the
 * thread can still do once it is asked to stop. It finishes the buffer it is handling (a
 * command and a send), sends QUIESCE_IO, gives back buffers in poll mode (the confirmation
 * time plus one command), collects the last READY_FOR_DATA reply, and waits for the
 * confirmation (that time plus one reply). One second more covers the back-off sleep and
 * scheduling.
 */
#define IPTS_RECEIVER_STOP_TIMEOUT_MS                                                       \
	(2 * IPTS_RECEIVER_CMD_MS + 2 * IPTS_MEI_SEND_TIMEOUT_MS +                           \
	 2 * IPTS_RECEIVER_STOP_CONFIRM_MS + 2 * IPTS_CMD_DEFAULT_TIMEOUT + 1000)

int ipts_receiver_start(struct ipts_context *ipts);
int ipts_receiver_stop(struct ipts_context *ipts);

#endif /* IPTS_RECEIVER_H */
