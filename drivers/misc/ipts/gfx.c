// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 * Intel Precise Touch & Stylus
 * Copyright (c) 2016 Intel Corporation
 *
 */

#include <linux/delay.h>
#include <linux/kthread.h>

#include "ipts.h"
#include "msg-handler.h"
#include "params.h"
#include "state.h"
#include "../mei/mei_dev.h"

static void gfx_processing_complete(void *data)
{
	struct ipts_info *ipts = data;

	if (ipts_get_state(ipts) == IPTS_STA_RAW_DATA_STARTED) {
		schedule_work(&ipts->raw_data_work);
		return;
	}

	ipts_dbg(ipts, "not ready to handle gfx event\n");
}

static void notify_gfx_status(u32 status, void *data)
{
	struct ipts_info *ipts = data;

	ipts->gfx_status = status;
	schedule_work(&ipts->gfx_status_work);
}

static int connect_gfx(struct ipts_info *ipts)
{
	int ret = 0;
	struct ipts_connect connect;

	connect.client = ipts->cldev->dev.parent;
	connect.if_version = IPTS_INTERFACE_V1;
	connect.ipts_cb.workload_complete = gfx_processing_complete;
	connect.ipts_cb.notify_gfx_status = notify_gfx_status;
	connect.data = (void *)ipts;

	ret = ipts_connect(&connect);
	if (ret)
		return ret;

	// TODO: GFX version check
	ipts->gfx_info.gfx_handle = connect.gfx_handle;
	ipts->gfx_info.ipts_ops = connect.ipts_ops;

	return ret;
}

static void disconnect_gfx(struct ipts_info *ipts)
{
	ipts_disconnect(ipts->gfx_info.gfx_handle);
}

static struct task_struct *dbg_thread;

static void ipts_print_dbg_info(struct ipts_info *ipts)
{
	char fw_sts_str[MEI_FW_STATUS_STR_SZ];
	u32 *db, *head, *tail;
	struct ipts_wq_info *wq_info;

	wq_info = &ipts->resource.wq_info;

	mei_fw_status_str(ipts->cldev->bus, fw_sts_str, MEI_FW_STATUS_STR_SZ);
	pr_info(">> tdt : fw status : %s\n", fw_sts_str);

	db = (u32 *)wq_info->db_addr;
	head = (u32 *)wq_info->wq_head_addr;
	tail = (u32 *)wq_info->wq_tail_addr;

	// Every time the ME has filled up the touch input buffer, and the GuC
	// doorbell is rang, the doorbell count will increase by one
	// The workqueue is the queue of touch events that the GuC has to
	// process. Head is the currently processed event, while tail is
	// the last one that is currently available. If head and tail are
	// not equal, this can be an indicator for GuC / GPU hang.
	pr_info(">> == Doorbell status:%x, count:%x ==\n", *db, *(db+1));
	pr_info(">> == Workqueue head:%u, tail:%u ==\n", *head, *tail);
}

static int ipts_dbg_thread(void *data)
{
	struct ipts_info *ipts = (struct ipts_info *)data;

	pr_info(">> start debug thread\n");

	while (!kthread_should_stop()) {
		if (ipts_get_state(ipts) != IPTS_STA_RAW_DATA_STARTED) {
			pr_info("state is not IPTS_STA_RAW_DATA_STARTED : %d\n",
				ipts_get_state(ipts));

			msleep(5000);
			continue;
		}

		ipts_print_dbg_info(ipts);
		msleep(3000);
	}

	return 0;
}

int ipts_open_gpu(struct ipts_info *ipts)
{
	int ret = 0;

	ret = connect_gfx(ipts);
	if (ret) {
		ipts_dbg(ipts, "cannot connect GPU\n");
		return ret;
	}

	ret = ipts->gfx_info.ipts_ops.get_wq_info(ipts->gfx_info.gfx_handle,
		&ipts->resource.wq_info);
	if (ret) {
		ipts_dbg(ipts, "error in get_wq_info\n");
		return ret;
	}

	if (ipts_modparams.debug_thread)
		dbg_thread = kthread_run(
			ipts_dbg_thread, (void *)ipts, "ipts_debug");

	return 0;
}

void ipts_close_gpu(struct ipts_info *ipts)
{
	disconnect_gfx(ipts);

	if (ipts_modparams.debug_thread)
		kthread_stop(dbg_thread);
}

struct ipts_mapbuffer *ipts_map_buffer(struct ipts_info *ipts,
		u32 size, u32 flags)
{
	struct ipts_mapbuffer *buf;
	u64 handle;
	int ret;

	buf = devm_kzalloc(&ipts->cldev->dev, sizeof(*buf), GFP_KERNEL);
	if (!buf)
		return NULL;

	buf->size = size;
	buf->flags = flags;

	handle = ipts->gfx_info.gfx_handle;
	ret = ipts->gfx_info.ipts_ops.map_buffer(handle, buf);
	if (ret) {
		devm_kfree(&ipts->cldev->dev, buf);
		return NULL;
	}

	return buf;
}

void ipts_unmap_buffer(struct ipts_info *ipts, struct ipts_mapbuffer *buf)
{
	u64 handle;

	if (!buf)
		return;

	handle = ipts->gfx_info.gfx_handle;
	ipts->gfx_info.ipts_ops.unmap_buffer(handle, buf->buf_handle);
	devm_kfree(&ipts->cldev->dev, buf);
}
