// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/mei_cl_bus.h>
#include <linux/types.h>

#include "context.h"
#include "protocol.h"
#include "resources.h"
#include "uapi.h"

int ipts_control_send(struct ipts_context *ipts,
		u32 cmd, void *data, u32 size)
{
	int ret;
	struct ipts_command msg;

	msg.code = cmd;

	// Copy message payload
	if (data && size > 0)
		memcpy(&msg.data, data, size);

	ret = mei_cldev_send(ipts->cldev, (u8 *)&msg, sizeof(msg.code) + size);
	if (ret >= 0)
		return 0;

	if (cmd == IPTS_CMD(FEEDBACK) && ret == -IPTS_ME_STATUS_NOT_READY)
		return 0;

	dev_err(ipts->dev, "MEI error while sending: 0x%X:%d\n", cmd, ret);

	return ret;
}

int ipts_control_start(struct ipts_context *ipts)
{
	ipts->status = IPTS_HOST_STATUS_STARTING;
	ipts_uapi_init(ipts);

	return ipts_control_send(ipts, IPTS_CMD(NOTIFY_DEV_READY), NULL, 0);
}

void ipts_control_stop(struct ipts_context *ipts)
{
	ipts->status = IPTS_HOST_STATUS_STOPPED;

	ipts_control_send(ipts, IPTS_CMD(QUIESCE_IO), NULL, 0);
	ipts_control_send(ipts, IPTS_CMD(CLEAR_MEM_WINDOW), NULL, 0);

	ipts_uapi_free(ipts);
	ipts_resources_free(ipts);
}

int ipts_control_restart(struct ipts_context *ipts)
{
	if (ipts->status == IPTS_HOST_STATUS_RESTARTING)
		return 0;

	dev_info(ipts->dev, "Restarting IPTS\n");
	ipts->status = IPTS_HOST_STATUS_RESTARTING;

	return ipts_control_send(ipts, IPTS_CMD(QUIESCE_IO), NULL, 0);
}
