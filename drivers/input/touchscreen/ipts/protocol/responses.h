/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _IPTS_PROTOCOL_RESPONSES_H_
#define _IPTS_PROTOCOL_RESPONSES_H_

#include <linux/build_bug.h>
#include <linux/types.h>

enum ipts_me_status {
	IPTS_ME_STATUS_SUCCESS = 0,
	IPTS_ME_STATUS_INVALID_PARAMS,
	IPTS_ME_STATUS_ACCESS_DENIED,
	IPTS_ME_STATUS_CMD_SIZE_ERROR,
	IPTS_ME_STATUS_NOT_READY,
	IPTS_ME_STATUS_REQUEST_OUTSTANDING,
	IPTS_ME_STATUS_NO_SENSOR_FOUND,
	IPTS_ME_STATUS_OUT_OF_MEMORY,
	IPTS_ME_STATUS_INTERNAL_ERROR,
	IPTS_ME_STATUS_SENSOR_DISABLED,
	IPTS_ME_STATUS_COMPAT_CHECK_FAIL,
	IPTS_ME_STATUS_SENSOR_EXPECTED_RESET,
	IPTS_ME_STATUS_SENSOR_UNEXPECTED_RESET,
	IPTS_ME_STATUS_RESET_FAILED,
	IPTS_ME_STATUS_TIMEOUT,
	IPTS_ME_STATUS_TEST_MODE_FAIL,
	IPTS_ME_STATUS_SENSOR_FAIL_FATAL,
	IPTS_ME_STATUS_SENSOR_FAIL_NONFATAL,
	IPTS_ME_STATUS_INVALID_DEVICE_CAPS,
	IPTS_ME_STATUS_QUIESCE_IO_IN_PROGRESS,
	IPTS_ME_STATUS_MAX
};

struct ipts_device_info {
	u16 vendor_id;
	u16 device_id;
	u32 hw_rev;
	u32 fw_rev;

	/* Required size of one touch data buffer */
	u32 data_size;

	/* Required size of one feedback buffer */
	u32 feedback_size;
	u8 reserved[24];
} __packed;

/*
 * Responses are sent from the ME to the host, reacting to a command.
 */
struct ipts_response {
	u32 code;
	u32 status;
	union {
		struct ipts_device_info device_info;
		u8 reserved[80];
	} data;
} __packed;

static_assert(sizeof(struct ipts_device_info) == 44);
static_assert(sizeof(struct ipts_response) == 88);

#endif /* _IPTS_PROTOCOL_RESPONSES_H_ */
