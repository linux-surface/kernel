// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/mei_cl_bus.h>
#include <linux/types.h>

#include "context.h"
#include "data.h"
#include "params.h"
#include "protocol/commands.h"
#include "protocol/events.h"
#include "protocol/feedback.h"
#include "resources.h"

int ipts_control_send(struct ipts_context *ipts,
		u32 cmd, void *data, u32 size)
{
	int ret;
	struct ipts_command msg;

	memset(&msg, 0, sizeof(struct ipts_command));
	msg.code = cmd;

	// Copy message payload
	if (data && size > 0)
		memcpy(&msg.data, data, size);

	ret = mei_cldev_send(ipts->client_dev, (u8 *)&msg,
			sizeof(msg.code) + size);
	if (ret < 0) {
		dev_err(ipts->dev, "%s: error 0x%X:%d\n", __func__, cmd, ret);
		return ret;
	}

	return 0;
}

int ipts_control_send_feedback(struct ipts_context *ipts,
		u32 buffer, u32 transaction)
{
	struct ipts_buffer_info feedback_buffer;
	struct ipts_feedback *feedback;
	struct ipts_feedback_cmd cmd;

	feedback_buffer = ipts->feedback[buffer];
	feedback = (struct ipts_feedback *)feedback_buffer.address;

	memset(feedback, 0, sizeof(struct ipts_feedback));
	memset(&cmd, 0, sizeof(struct ipts_feedback_cmd));

	feedback->type = IPTS_FEEDBACK_TYPE_NONE;
	feedback->transaction = transaction;

	cmd.buffer = buffer;
	cmd.transaction = transaction;

	return ipts_control_send(ipts, IPTS_CMD(FEEDBACK),
			&cmd, sizeof(struct ipts_feedback_cmd));
}

int ipts_control_start(struct ipts_context *ipts)
{
	ipts->status = IPTS_HOST_STATUS_INIT;

	if (ipts_params.singletouch)
		ipts->mode = IPTS_SENSOR_MODE_SINGLETOUCH;
	else
		ipts->mode = IPTS_SENSOR_MODE_MULTITOUCH;

	return ipts_control_send(ipts, IPTS_CMD(NOTIFY_DEV_READY), NULL, 0);
}

void ipts_control_stop(struct ipts_context *ipts)
{
	enum ipts_host_status old_status = ipts->status;

	ipts->status = IPTS_HOST_STATUS_STOPPING;
	ipts_control_send(ipts, IPTS_CMD(QUIESCE_IO), NULL, 0);
	ipts_control_send(ipts, IPTS_CMD(CLEAR_MEM_WINDOW), NULL, 0);

	if (old_status < IPTS_HOST_STATUS_RESOURCE_READY)
		return;

	ipts_data_free(ipts);
	ipts_resources_free(ipts);
}

int ipts_control_restart(struct ipts_context *ipts)
{
	dev_info(ipts->dev, "Restarting IPTS\n");
	ipts_control_stop(ipts);

	ipts->status = IPTS_HOST_STATUS_RESTARTING;
	return ipts_control_send(ipts, IPTS_CMD(QUIESCE_IO), NULL, 0);
}
