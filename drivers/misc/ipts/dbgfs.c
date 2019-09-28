// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 * Intel Precise Touch & Stylus
 * Copyright (c) 2016 Intel Corporation
 *
 */

#include <linux/ctype.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>

#include "ipts.h"
#include "msg-handler.h"
#include "sensor-regs.h"
#include "state.h"
#include "../mei/mei_dev.h"

static const char ipts_status_fmt[] = "ipts state : %01d\n";
static const char ipts_debug_fmt[] = ">> tdt : fw status : %s\n"
	">> == Doorbell status:%x, count:%x ==\n"
	">> == Workqueue head:%u, tail:%u ==\n";

static ssize_t ipts_dbgfs_status_read(struct file *fp, char __user *ubuf,
		size_t cnt, loff_t *ppos)
{
	struct ipts_info *ipts = fp->private_data;
	char status[256];
	int len = 0;

	if (cnt < sizeof(ipts_status_fmt) - 3)
		return -EINVAL;

	len = scnprintf(status, 256, ipts_status_fmt, ipts->state);
	if (len < 0)
		return -EIO;

	return simple_read_from_buffer(ubuf, cnt, ppos, status, len);
}

static const struct file_operations ipts_status_dbgfs_fops = {
	.open = simple_open,
	.read = ipts_dbgfs_status_read,
	.llseek = generic_file_llseek,
};

static ssize_t ipts_dbgfs_quiesce_io_cmd_write(struct file *fp,
		const char __user *ubuf, size_t cnt, loff_t *ppos)
{
	struct ipts_info *ipts = fp->private_data;
	bool result;
	int rc;

	rc = kstrtobool_from_user(ubuf, cnt, &result);
	if (rc)
		return rc;

	if (!result)
		return -EINVAL;

	ipts_send_sensor_quiesce_io_cmd(ipts);
	return cnt;
}

static const struct file_operations ipts_quiesce_io_cmd_dbgfs_fops = {
	.open = simple_open,
	.write = ipts_dbgfs_quiesce_io_cmd_write,
	.llseek = generic_file_llseek,
};

static ssize_t ipts_dbgfs_clear_mem_window_cmd_write(struct file *fp,
		const char __user *ubuf, size_t cnt, loff_t *ppos)
{
	struct ipts_info *ipts = fp->private_data;
	bool result;
	int rc;

	rc = kstrtobool_from_user(ubuf, cnt, &result);
	if (rc)
		return rc;

	if (!result)
		return -EINVAL;

	ipts_send_sensor_clear_mem_window_cmd(ipts);

	return cnt;
}

static const struct file_operations ipts_clear_mem_window_cmd_dbgfs_fops = {
	.open = simple_open,
	.write = ipts_dbgfs_clear_mem_window_cmd_write,
	.llseek = generic_file_llseek,
};

static ssize_t ipts_dbgfs_debug_read(struct file *fp, char __user *ubuf,
		size_t cnt, loff_t *ppos)
{
	struct ipts_info *ipts = fp->private_data;
	char dbg_info[1024];
	int len = 0;

	char fw_sts_str[MEI_FW_STATUS_STR_SZ];
	u32 *db, *head, *tail;
	struct ipts_wq_info *wq_info;

	wq_info = &ipts->resource.wq_info;
	mei_fw_status_str(ipts->cldev->bus, fw_sts_str, MEI_FW_STATUS_STR_SZ);

	db = (u32 *)wq_info->db_addr;
	head = (u32 *)wq_info->wq_head_addr;
	tail = (u32 *)wq_info->wq_tail_addr;

	if (cnt < sizeof(ipts_debug_fmt) - 3)
		return -EINVAL;

	len = scnprintf(dbg_info, 1024, ipts_debug_fmt,
		fw_sts_str, *db, *(db+1), *head, *tail);

	if (len < 0)
		return -EIO;

	return simple_read_from_buffer(ubuf, cnt, ppos, dbg_info, len);
}

static const struct file_operations ipts_debug_dbgfs_fops = {
	.open = simple_open,
	.read = ipts_dbgfs_debug_read,
	.llseek = generic_file_llseek,
};

static ssize_t ipts_dbgfs_ipts_restart_write(struct file *fp,
		const char __user *ubuf, size_t cnt, loff_t *ppos)
{
	struct ipts_info *ipts = fp->private_data;
	bool result;
	int rc;

	rc = kstrtobool_from_user(ubuf, cnt, &result);
	if (rc)
		return rc;
	if (!result)
		return -EINVAL;

	ipts_restart(ipts);
	return cnt;
}

static const struct file_operations ipts_ipts_restart_dbgfs_fops = {
	.open = simple_open,
	.write = ipts_dbgfs_ipts_restart_write,
	.llseek = generic_file_llseek,
};

static ssize_t ipts_dbgfs_ipts_stop_write(struct file *fp,
		const char __user *ubuf, size_t cnt, loff_t *ppos)
{
	struct ipts_info *ipts = fp->private_data;
	bool result;
	int rc;

	rc = kstrtobool_from_user(ubuf, cnt, &result);
	if (rc)
		return rc;

	if (!result)
		return -EINVAL;

	ipts_stop(ipts);
	return cnt;
}

static const struct file_operations ipts_ipts_stop_dbgfs_fops = {
	.open = simple_open,
	.write = ipts_dbgfs_ipts_stop_write,
	.llseek = generic_file_llseek,
};

static ssize_t ipts_dbgfs_ipts_start_write(struct file *fp,
		const char __user *ubuf, size_t cnt, loff_t *ppos)
{
	struct ipts_info *ipts = fp->private_data;
	bool result;
	int rc;

	rc = kstrtobool_from_user(ubuf, cnt, &result);
	if (rc)
		return rc;

	if (!result)
		return -EINVAL;

	ipts_start(ipts);
	return cnt;
}

static const struct file_operations ipts_ipts_start_dbgfs_fops = {
	.open = simple_open,
	.write = ipts_dbgfs_ipts_start_write,
	.llseek = generic_file_llseek,
};

void ipts_dbgfs_deregister(struct ipts_info *ipts)
{
	if (!ipts->dbgfs_dir)
		return;

	debugfs_remove_recursive(ipts->dbgfs_dir);
	ipts->dbgfs_dir = NULL;
}

int ipts_dbgfs_register(struct ipts_info *ipts, const char *name)
{
	struct dentry *dir, *f;

	dir = debugfs_create_dir(name, NULL);
	if (!dir)
		return -ENOMEM;

	f = debugfs_create_file("status", 0200, dir, ipts,
		&ipts_status_dbgfs_fops);
	if (!f) {
		ipts_err(ipts, "debugfs status creation failed\n");
		goto err;
	}

	f = debugfs_create_file("quiesce_io_cmd", 0200, dir, ipts,
		&ipts_quiesce_io_cmd_dbgfs_fops);
	if (!f) {
		ipts_err(ipts, "debugfs quiesce_io_cmd creation failed\n");
		goto err;
	}

	f = debugfs_create_file("clear_mem_window_cmd", 0200, dir, ipts,
		&ipts_clear_mem_window_cmd_dbgfs_fops);
	if (!f) {
		ipts_err(ipts, "debugfs clear_mem_window_cmd creation failed\n");
		goto err;
	}

	f = debugfs_create_file("debug", 0200, dir, ipts,
		&ipts_debug_dbgfs_fops);
	if (!f) {
		ipts_err(ipts, "debugfs debug creation failed\n");
		goto err;
	}

	f = debugfs_create_file("ipts_restart", 0200, dir, ipts,
		&ipts_ipts_restart_dbgfs_fops);
	if (!f) {
		ipts_err(ipts, "debugfs ipts_restart creation failed\n");
		goto err;
	}

	f = debugfs_create_file("ipts_stop", 0200, dir, ipts,
		&ipts_ipts_stop_dbgfs_fops);
	if (!f) {
		ipts_err(ipts, "debugfs ipts_stop creation failed\n");
		goto err;
	}

	f = debugfs_create_file("ipts_start", 0200, dir, ipts,
		&ipts_ipts_start_dbgfs_fops);
	if (!f) {
		ipts_err(ipts, "debugfs ipts_start creation failed\n");
		goto err;
	}

	ipts->dbgfs_dir = dir;

	return 0;

err:
	ipts_dbgfs_deregister(ipts);

	return -ENODEV;
}
