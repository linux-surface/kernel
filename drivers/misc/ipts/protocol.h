/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _IPTS_PROTOCOL_H_
#define _IPTS_PROTOCOL_H_

#include <linux/build_bug.h>
#include <linux/types.h>

#define IPTS_WORKQUEUE_SIZE 8192
#define IPTS_WORKQUEUE_ITEM_SIZE 16

/*
 * How many data / feedback buffers IPTS uses
 */
#define IPTS_BUFFERS 16

/*
 * Helpers to avoid writing boilerplate code.
 * The response to a command code is always 0x8000000x, where x
 * is the command code itself. Instead of writing two definitions,
 * we use macros to calculate the value on the fly instead.
 */
#define IPTS_CMD(COMMAND) IPTS_EVT_##COMMAND
#define IPTS_RSP(COMMAND) (IPTS_CMD(COMMAND) + 0x80000000)

/*
 * enum ipts_evt_code - Events that can be sent and received from the ME
 *
 * Events can describe either a command (sent from host to ME) or a
 * response (sent from ME to host). These values should not be used
 * directly, instead they should be wrapped with the appropreate
 * IPTS_CMD / IPTS_RSP macro, to clearly document the wanted event type.
 */
enum ipts_evt_code {
	IPTS_EVT_GET_DEVICE_INFO = 1,
	IPTS_EVT_SET_MODE,
	IPTS_EVT_SET_MEM_WINDOW,
	IPTS_EVT_QUIESCE_IO,
	IPTS_EVT_READY_FOR_DATA,
	IPTS_EVT_FEEDBACK,
	IPTS_EVT_CLEAR_MEM_WINDOW,
	IPTS_EVT_NOTIFY_DEV_READY,
};

/*
 * enum ipts_me_status - Status codes returned in response to a command.
 *
 * These codes are returned by the ME to indicate whether a command was
 * executed successfully.
 *
 * Some of these errors are less serious than others, and some need to be
 * ignored to ensure proper operation. See also ipts_receiver_handle_error.
 */
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

/*
 * enum ipts_sensor_mode - The sensor mode for IPTS to use
 *
 * IPTS_SENSOR_MODE_SINGLETOUCH:
 *
 *   Singletouch mode is a fallback mode that does not support the stylus
 *   or more than one touch input. The data is received as a HID report with
 *   report ID 64.
 *
 * IPTS_SENSOR_MODE_MULTITOUCH:
 *
 *   Multitouch mode is the proper operation mode for IPTS. It will return
 *   stylus data, as well as touch data as a raw heatmap directly from
 *   the sensor. This data needs to be processed before it can be used
 *   for input devices.
 *
 * This driver only supports multitouch mode.
 */
enum ipts_sensor_mode {
	IPTS_SENSOR_MODE_SINGLETOUCH = 0,
	IPTS_SENSOR_MODE_MULTITOUCH,
};

/*
 * struct ipts_set_mode_cmd - Parameters for the SET_MODE command.
 *
 * @sensor_mode: The mode which the touch sensor should operate in
 *               (from enum ipts_sensor_mode).
 *
 * On newer generations of IPTS (surface gen7) this command will only accept
 * IPTS_SENSOR_MODE_MULTITOUCH, and fail if anything else is sent.
 */
struct ipts_set_mode_cmd {
	u32 sensor_mode;
	u8 reserved[12];
} __packed;

static_assert(sizeof(struct ipts_set_mode_cmd) == 16);

/*
 * struct ipts_set_mem_window_cmd - Parameters for the SET_MEM_WINDOW command.
 *
 * This passes the physical addresses of buffers to the ME, which are
 * the used to exchange data between host and ME.
 *
 * Some of these buffers are not used by the host. They are a leftover from
 * when IPTS used binary firmware with GuC submission. They need to be
 * allocated and passed, otherwise the command will not return successfully.
 *
 * For a description of the various buffers, please check out the ipts_context
 * struct and it's documentation.
 */
struct ipts_set_mem_window_cmd {
	u32 data_buffer_addr_lower[IPTS_BUFFERS];
	u32 data_buffer_addr_upper[IPTS_BUFFERS];
	u32 workqueue_addr_lower;
	u32 workqueue_addr_upper;
	u32 doorbell_addr_lower;
	u32 doorbell_addr_upper;
	u32 feedback_buffer_addr_lower[IPTS_BUFFERS];
	u32 feedback_buffer_addr_upper[IPTS_BUFFERS];
	u32 host2me_addr_lower;
	u32 host2me_addr_upper;
	u32 host2me_size;
	u8 reserved1;
	u8 workqueue_item_size;
	u16 workqueue_size;
	u8 reserved[32];
} __packed;

static_assert(sizeof(struct ipts_set_mem_window_cmd) == 320);

/*
 * struct ipts_feedback_cmd - Parameters for the FEEDBACK command.
 *
 * This command is sent to indicate that the data in a buffer has been
 * processed by the host, and that the ME can safely overwrite the data.
 *
 * @buffer: The buffer to be refilled
 */
struct ipts_feedback_cmd {
	u32 buffer;
	u8 reserved[12];
} __packed;

static_assert(sizeof(struct ipts_feedback_cmd) == 16);

/*
 * struct ipts_command - Describes a command sent from the host to the ME.
 *
 * @code: The command code. (IPTS_CMD(EVENT))
 * @set_mode: The parameters for the SET_MODE command
 * @set_mem_window: The parameters for the SET_MEM_WINDOW command
 * @feedback: The parameters for the FEEDBACK command.
 *
 * This struct should always be initialized with 0, to prevent the ME
 * from interpreting random bytes as a parameter.
 *
 * The ME will react to a command by sending a response, indicating if
 * the command was successfully, and returning queried data.
 */
struct ipts_command {
	u32 code;
	union {
		struct ipts_set_mode_cmd set_mode;
		struct ipts_set_mem_window_cmd set_mem_window;
		struct ipts_feedback_cmd feedback;
	} data;
} __packed;

static_assert(sizeof(struct ipts_command) == 324);

/*
 * struct ipts_device_info - Returned by the GET_DEVICE_INFO command.
 *
 * @vendor_id: Vendor ID of the touch sensor
 * @device_id: Device ID of the touch sensor
 * @hw_rev: Hardware revision of the touch sensor
 * @fw_rev: Firmware revision of the touch sensor
 * @data_size: Required size of one data buffer
 * @feedback_size: Required size of one feedback buffer
 * @max_touch_points: The amount of concurrent touches supported by the sensor
 */
struct ipts_device_info {
	u16 vendor_id;
	u16 device_id;
	u32 hw_rev;
	u32 fw_rev;
	u32 data_size;
	u32 feedback_size;
	u8 reserved1[4];
	u8 max_touch_points;
	u8 reserved[19];
} __packed;

static_assert(sizeof(struct ipts_device_info) == 44);

/*
 * struct ipts_response - Describes the response from the ME to a command.
 *
 * @code: The response code. (0x80000000 + command code that was sent)
 * @status: The return value of the command. (from enum ipts_me_status)
 * @device_info: The data that was queried by the GET_DEVICE_INFO command.
 *
 * Theoretically all commands could return data but only the data from
 * GET_DEVICE_INFO is relevant for the host.
 */
struct ipts_response {
	u32 code;
	u32 status;
	union {
		struct ipts_device_info device_info;
		u8 reserved[80];
	} data;
} __packed;

static_assert(sizeof(struct ipts_response) == 88);

#endif /* _IPTS_PROTOCOL_H_ */
