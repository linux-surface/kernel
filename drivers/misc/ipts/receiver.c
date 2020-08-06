// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/mei_cl_bus.h>
#include <linux/types.h>

#include "context.h"
#include "control.h"
#include "protocol.h"
#include "resources.h"
#include "uapi.h"

static int ipts_receiver_handle_notify_dev_ready(struct ipts_context *ipts)
{
	return ipts_control_send(ipts, IPTS_CMD(GET_DEVICE_INFO), NULL, 0);
}

static int ipts_receiver_handle_get_device_info(struct ipts_context *ipts,
		struct ipts_response *msg)
{
	memcpy(&ipts->device_info, &msg->data.device_info,
			sizeof(struct ipts_device_info));

	dev_info(ipts->dev, "Device %04hX:%04hX found\n",
			ipts->device_info.vendor_id,
			ipts->device_info.device_id);

	return ipts_control_send(ipts, IPTS_CMD(CLEAR_MEM_WINDOW), NULL, 0);
}

static int ipts_receiver_handle_clear_mem_window(struct ipts_context *ipts)
{
	struct ipts_set_mode_cmd sensor_mode_cmd;

	memset(&sensor_mode_cmd, 0, sizeof(struct ipts_set_mode_cmd));
	sensor_mode_cmd.sensor_mode = IPTS_SENSOR_MODE_MULTITOUCH;

	return ipts_control_send(ipts, IPTS_CMD(SET_MODE),
			&sensor_mode_cmd, sizeof(struct ipts_set_mode_cmd));
}

static int ipts_receiver_handle_set_mode(struct ipts_context *ipts)
{
	int i, ret;
	struct ipts_set_mem_window_cmd cmd;

	ret = ipts_resources_init(ipts);
	if (ret)
		return ret;

	memset(&cmd, 0, sizeof(struct ipts_set_mem_window_cmd));

	for (i = 0; i < IPTS_BUFFERS; i++) {
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

	cmd.workqueue_size = IPTS_WORKQUEUE_SIZE;
	cmd.workqueue_item_size = IPTS_WORKQUEUE_ITEM_SIZE;

	return ipts_control_send(ipts, IPTS_CMD(SET_MEM_WINDOW),
			&cmd, sizeof(struct ipts_set_mem_window_cmd));
}

static int ipts_receiver_handle_set_mem_window(struct ipts_context *ipts)
{
	ipts->status = IPTS_HOST_STATUS_STARTED;
	dev_info(ipts->dev, "IPTS enabled\n");

	return ipts_control_send(ipts, IPTS_CMD(READY_FOR_DATA), NULL, 0);
}

static int ipts_receiver_handle_quiesce_io(struct ipts_context *ipts)
{
	if (ipts->status != IPTS_HOST_STATUS_RESTARTING)
		return 0;

	ipts_uapi_free(ipts);
	ipts_resources_free(ipts);

	return ipts_control_start(ipts);
}

static bool ipts_receiver_handle_error(struct ipts_context *ipts,
		struct ipts_response *msg)
{
	bool error;
	bool restart;

	switch (msg->status) {
	case IPTS_ME_STATUS_SUCCESS:
	case IPTS_ME_STATUS_COMPAT_CHECK_FAIL:
		error = false;
		restart = false;
		break;
	case IPTS_ME_STATUS_INVALID_PARAMS:
		error = msg->code != IPTS_RSP(FEEDBACK);
		restart = false;
		break;
	case IPTS_ME_STATUS_SENSOR_DISABLED:
		error = msg->code != IPTS_RSP(READY_FOR_DATA);
		restart = false;
		break;
	case IPTS_ME_STATUS_TIMEOUT:
		error = msg->code != IPTS_RSP(CLEAR_MEM_WINDOW);
		restart = false;
		break;
	case IPTS_ME_STATUS_SENSOR_EXPECTED_RESET:
	case IPTS_ME_STATUS_SENSOR_UNEXPECTED_RESET:
		error = true;
		restart = true;
		break;
	default:
		error = true;
		restart = false;
		break;
	}

	if (!error)
		return false;

	dev_err(ipts->dev, "0x%08x failed: %d\n", msg->code, msg->status);

	if (restart) {
		dev_err(ipts->dev, "Sensor reset: %d\n", msg->status);
		ipts_control_restart(ipts);
	}

	return true;
}

static void ipts_receiver_handle_response(struct ipts_context *ipts,
		struct ipts_response *msg)
{
	int ret = 0;

	if (ipts_receiver_handle_error(ipts, msg))
		return;

	switch (msg->code) {
	case IPTS_RSP(NOTIFY_DEV_READY):
		ret = ipts_receiver_handle_notify_dev_ready(ipts);
		break;
	case IPTS_RSP(GET_DEVICE_INFO):
		ret = ipts_receiver_handle_get_device_info(ipts, msg);
		break;
	case IPTS_RSP(CLEAR_MEM_WINDOW):
		ret = ipts_receiver_handle_clear_mem_window(ipts);
		break;
	case IPTS_RSP(SET_MODE):
		ret = ipts_receiver_handle_set_mode(ipts);
		break;
	case IPTS_RSP(SET_MEM_WINDOW):
		ret = ipts_receiver_handle_set_mem_window(ipts);
		break;
	case IPTS_RSP(QUIESCE_IO):
		ret = ipts_receiver_handle_quiesce_io(ipts);
		break;
	}

	if (!ret)
		return;

	dev_err(ipts->dev, "Detected MEI bus error\n");
	dev_err(ipts->dev, "Stopping IPTS\n");

	ipts->status = IPTS_HOST_STATUS_STOPPED;
}

void ipts_receiver_callback(struct mei_cl_device *cldev)
{
	struct ipts_response msg;
	struct ipts_context *ipts = mei_cldev_get_drvdata(cldev);

	if (mei_cldev_recv(ipts->cldev, (u8 *)&msg, sizeof(msg)) <= 0) {
		dev_err(ipts->dev, "Error while reading MEI message\n");
		return;
	}

	if (ipts->status == IPTS_HOST_STATUS_STOPPED)
		return;

	ipts_receiver_handle_response(ipts, &msg);
}
