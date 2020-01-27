// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/types.h>

#include "context.h"
#include "control.h"
#include "data.h"
#include "protocol/commands.h"
#include "protocol/events.h"
#include "protocol/responses.h"
#include "resources.h"

static void ipts_receiver_handle_notify_dev_ready(struct ipts_context *ipts,
		struct ipts_response *msg, int *cmd_status)
{
	if (msg->status != IPTS_ME_STATUS_SENSOR_FAIL_NONFATAL &&
			msg->status != IPTS_ME_STATUS_SUCCESS) {
		dev_err(ipts->dev, "0x%08x failed - status = %d\n",
				msg->code, msg->status);
		return;
	}

	*cmd_status = ipts_control_send(ipts,
			IPTS_CMD(GET_DEVICE_INFO), NULL, 0);
}

static void ipts_receiver_handle_get_device_info(struct ipts_context *ipts,
		struct ipts_response *msg, int *cmd_status)
{
	if (msg->status != IPTS_ME_STATUS_COMPAT_CHECK_FAIL &&
			msg->status != IPTS_ME_STATUS_SUCCESS) {
		dev_err(ipts->dev, "0x%08x failed - status = %d\n",
				msg->code, msg->status);
		return;
	}

	memcpy(&ipts->device_info, &msg->data.device_info,
			sizeof(struct ipts_device_info));

	dev_info(ipts->dev, "Device %04hX:%04hX found\n",
			ipts->device_info.vendor_id,
			ipts->device_info.device_id);

	if (ipts_data_init(ipts))
		return;

	*cmd_status = ipts_control_send(ipts,
			IPTS_CMD(CLEAR_MEM_WINDOW), NULL, 0);
}

static void ipts_receiver_handle_clear_mem_window(struct ipts_context *ipts,
		struct ipts_response *msg, int *cmd_status, int *ret)
{
	struct ipts_set_mode_cmd sensor_mode_cmd;

	if (msg->status != IPTS_ME_STATUS_TIMEOUT &&
			msg->status != IPTS_ME_STATUS_SUCCESS) {
		dev_err(ipts->dev, "0x%08x failed - status = %d\n",
				msg->code, msg->status);
		return;
	}

	if (ipts->status == IPTS_HOST_STATUS_STOPPING)
		return;

	if (ipts_resources_init(ipts))
		return;

	ipts->status = IPTS_HOST_STATUS_RESOURCE_READY;

	memset(&sensor_mode_cmd, 0, sizeof(struct ipts_set_mode_cmd));
	sensor_mode_cmd.sensor_mode = ipts->mode;

	*cmd_status = ipts_control_send(ipts, IPTS_CMD(SET_MODE),
			&sensor_mode_cmd, sizeof(struct ipts_set_mode_cmd));
}

static void ipts_receiver_handle_set_mode(struct ipts_context *ipts,
		struct ipts_response *msg, int *cmd_status)
{
	int i;
	struct ipts_set_mem_window_cmd cmd;

	if (msg->status != IPTS_ME_STATUS_SUCCESS) {
		dev_err(ipts->dev, "0x%08x failed - status = %d\n",
				msg->code, msg->status);
		return;
	}

	memset(&cmd, 0, sizeof(struct ipts_set_mem_window_cmd));

	for (i = 0; i < 16; i++) {
		cmd.data_buffer_addr_lower[i] =
			lower_32_bits(ipts->data[i].dma_address);

		cmd.data_buffer_addr_upper[i] =
			upper_32_bits(ipts->data[i].dma_address);

		cmd.feedback_buffer_addr_lower[i] =
			lower_32_bits(ipts->feedback[i].dma_address);

		cmd.feedback_buffer_addr_upper[i] =
			upper_32_bits(ipts->feedback[i].dma_address);
	}

	cmd.workqueue_addr_lower = lower_32_bits(ipts->workqueue.dma_address);
	cmd.workqueue_addr_upper = upper_32_bits(ipts->workqueue.dma_address);

	cmd.doorbell_addr_lower = lower_32_bits(ipts->doorbell.dma_address);
	cmd.doorbell_addr_upper = upper_32_bits(ipts->doorbell.dma_address);

	cmd.host2me_addr_lower = lower_32_bits(ipts->host2me.dma_address);
	cmd.host2me_addr_upper = upper_32_bits(ipts->host2me.dma_address);
	cmd.host2me_size = ipts->device_info.data_size;

	cmd.workqueue_size = 8192;
	cmd.workqueue_item_size = 16;

	*cmd_status = ipts_control_send(ipts, IPTS_CMD(SET_MEM_WINDOW),
			&cmd, sizeof(struct ipts_set_mem_window_cmd));
}

static void ipts_receiver_handle_set_mem_window(struct ipts_context *ipts,
		struct ipts_response *msg, int *cmd_status)
{
	if (msg->status != IPTS_ME_STATUS_SUCCESS) {
		dev_err(ipts->dev, "0x%08x failed - status = %d\n",
				msg->code, msg->status);
		return;
	}

	*cmd_status = ipts_control_send(ipts,
			IPTS_CMD(READY_FOR_DATA), NULL, 0);
	if (*cmd_status)
		return;

	ipts->status = IPTS_HOST_STATUS_STARTED;
	dev_info(ipts->dev, "IPTS enabled\n");
}

static void ipts_receiver_handle_ready_for_data(struct ipts_context *ipts,
		struct ipts_response *msg)
{
	if (msg->status != IPTS_ME_STATUS_SENSOR_DISABLED &&
			msg->status != IPTS_ME_STATUS_SUCCESS) {
		dev_err(ipts->dev, "0x%08x failed - status = %d\n",
				msg->code, msg->status);
		return;
	}

	if (ipts->mode != IPTS_SENSOR_MODE_SINGLETOUCH ||
			ipts->status != IPTS_HOST_STATUS_STARTED)
		return;

	// Increment the doorbell manually to indicate that a new buffer
	// filled with touch data is available
	*((u32 *)ipts->doorbell.address) += 1;
}

static void ipts_recever_handle_feedback(struct ipts_context *ipts,
		struct ipts_response *msg, int *cmd_status)
{
	if (msg->status != IPTS_ME_STATUS_COMPAT_CHECK_FAIL &&
			msg->status != IPTS_ME_STATUS_SUCCESS &&
			msg->status != IPTS_ME_STATUS_INVALID_PARAMS) {
		dev_err(ipts->dev, "0x%08x failed - status = %d\n",
				msg->code, msg->status);
		return;
	}

	if (ipts->mode != IPTS_SENSOR_MODE_SINGLETOUCH)
		return;

	*cmd_status = ipts_control_send(ipts,
			IPTS_CMD(READY_FOR_DATA), NULL, 0);
}

static void ipts_receiver_handle_quiesce_io(struct ipts_context *ipts,
		struct ipts_response *msg)
{
	if (msg->status != IPTS_ME_STATUS_SUCCESS) {
		dev_err(ipts->dev, "0x%08x failed - status = %d\n",
				msg->code, msg->status);
		return;
	}

	if (ipts->status == IPTS_HOST_STATUS_RESTARTING)
		ipts_control_start(ipts);
}


static int ipts_receiver_handle_response(struct ipts_context *ipts,
		struct ipts_response *msg, u32 msg_len)
{
	int cmd_status = 0;
	int ret = 0;

	switch (msg->code) {
	case IPTS_RSP(NOTIFY_DEV_READY):
		ipts_receiver_handle_notify_dev_ready(ipts, msg, &cmd_status);
		break;
	case IPTS_RSP(GET_DEVICE_INFO):
		ipts_receiver_handle_get_device_info(ipts, msg, &cmd_status);
		break;
	case IPTS_RSP(CLEAR_MEM_WINDOW):
		ipts_receiver_handle_clear_mem_window(ipts, msg,
				&cmd_status, &ret);
		break;
	case IPTS_RSP(SET_MODE):
		ipts_receiver_handle_set_mode(ipts, msg, &cmd_status);
		break;
	case IPTS_RSP(SET_MEM_WINDOW):
		ipts_receiver_handle_set_mem_window(ipts, msg, &cmd_status);
		break;
	case IPTS_RSP(READY_FOR_DATA):
		ipts_receiver_handle_ready_for_data(ipts, msg);
		break;
	case IPTS_RSP(FEEDBACK):
		ipts_recever_handle_feedback(ipts, msg, &cmd_status);
		break;
	case IPTS_RSP(QUIESCE_IO):
		ipts_receiver_handle_quiesce_io(ipts, msg);
		break;
	}

	if (ipts->status == IPTS_HOST_STATUS_STOPPING)
		return 0;

	if (msg->status == IPTS_ME_STATUS_SENSOR_UNEXPECTED_RESET ||
			msg->status == IPTS_ME_STATUS_SENSOR_EXPECTED_RESET) {
		dev_info(ipts->dev, "Sensor has been reset: %d\n", msg->status);
		ipts_control_restart(ipts);
	}

	if (cmd_status)
		ipts_control_restart(ipts);

	return ret;
}

int ipts_receiver_loop(void *data)
{
	u32 msg_len;
	struct ipts_context *ipts;
	struct ipts_response msg;

	ipts = (struct ipts_context *)data;
	dev_info(ipts->dev, "Starting receive loop\n");

	while (!kthread_should_stop()) {
		msg_len = mei_cldev_recv(ipts->client_dev,
			(u8 *)&msg, sizeof(msg));

		if (msg_len <= 0) {
			dev_err(ipts->dev, "Error in reading ME message\n");
			continue;
		}

		if (ipts_receiver_handle_response(ipts, &msg, msg_len))
			dev_err(ipts->dev, "Error in handling ME message\n");
	}

	dev_info(ipts->dev, "Stopping receive loop\n");
	return 0;
}
