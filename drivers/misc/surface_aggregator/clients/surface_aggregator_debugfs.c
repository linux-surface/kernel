// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * DebugFS interface for Surface System Aggregator Module (SSAM) controller
 * access from user-space. Intended for debugging and development.
 */

#include <linux/debugfs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include <linux/surface_aggregator/controller.h>

#define SSAM_DBG_DEVICE_NAME		"surface_aggregator_dbg"
#define SSAM_DBG_IF_VERSION		0x010000

/**
 * struct ssam_debug_request - Controller request IOCTL argument.
 * @target_category: Target category of the SAM request.
 * @target_id:       Target ID of the SAM request.
 * @command_id:      Command ID of the SAM request.
 * @instance_id:     Instance ID of the SAM request.
 * @flags:           SAM Request flags.
 * @status:          Request status (output).
 * @payload:         Request payload (input data).
 * @payload.data:    Pointer to request payload data.
 * @payload.length:  Length of request payload data (in bytes).
 * @response:        Request response (output data).
 * @response.data:   Pointer to response buffer.
 * @response.length: On input: Capacity of response buffer (in bytes).
 *                   On output: Length of request response (number of bytes
 *                   in the buffer that are actually used).
 */
struct ssam_dbg_request {
	__u8 target_category;
	__u8 target_id;
	__u8 command_id;
	__u8 instance_id;
	__u16 flags;
	__s16 status;

	struct {
		const __u8 __user *data;
		__u16 length;
		__u8 __pad[6];
	} payload;

	struct {
		__u8 __user *data;
		__u16 length;
		__u8 __pad[6];
	} response;
};

#define SSAM_DBG_IOCTL_GETVERSION  _IOR(0xA5, 0, __u32)
#define SSAM_DBG_IOCTL_REQUEST     _IOWR(0xA5, 1, struct ssam_dbg_request)

struct ssam_dbg_data {
	struct ssam_controller *ctrl;
	struct dentry *dentry_dir;
	struct dentry *dentry_dev;
};

static int ssam_dbg_device_open(struct inode *inode, struct file *filp)
{
	filp->private_data = inode->i_private;
	return nonseekable_open(inode, filp);
}

static long ssam_dbg_if_request(struct file *file, unsigned long arg)
{
	struct ssam_dbg_data *data = file->private_data;
	struct ssam_dbg_request __user *r;
	struct ssam_dbg_request rqst;
	struct ssam_request spec;
	struct ssam_response rsp;
	int status = 0, ret = 0, tmp;

	r = (struct ssam_dbg_request __user *)arg;
	ret = copy_struct_from_user(&rqst, sizeof(rqst), r, sizeof(*r));
	if (ret)
		goto out;

	// setup basic request fields
	spec.target_category = rqst.target_category;
	spec.target_id = rqst.target_id;
	spec.command_id = rqst.command_id;
	spec.instance_id = rqst.instance_id;
	spec.flags = rqst.flags;
	spec.length = rqst.payload.length;
	spec.payload = NULL;

	rsp.capacity = rqst.response.length;
	rsp.length = 0;
	rsp.pointer = NULL;

	// get request payload from user-space
	if (spec.length) {
		if (!rqst.payload.data) {
			ret = -EINVAL;
			goto out;
		}

		spec.payload = kzalloc(spec.length, GFP_KERNEL);
		if (!spec.payload) {
			status = -ENOMEM;
			ret = -EFAULT;
			goto out;
		}

		if (copy_from_user((void *)spec.payload, rqst.payload.data,
				   spec.length)) {
			ret = -EFAULT;
			goto out;
		}
	}

	// allocate response buffer
	if (rsp.capacity) {
		if (!rqst.response.data) {
			ret = -EINVAL;
			goto out;
		}

		rsp.pointer = kzalloc(rsp.capacity, GFP_KERNEL);
		if (!rsp.pointer) {
			status = -ENOMEM;
			ret = -EFAULT;
			goto out;
		}
	}

	// perform request
	status = ssam_request_sync(data->ctrl, &spec, &rsp);
	if (status)
		goto out;

	// copy response to user-space
	if (rsp.length) {
		if (copy_to_user(rqst.response.data, rsp.pointer, rsp.length)) {
			ret = -EFAULT;
			goto out;
		}
	}

out:
	// always try to set response-length and status
	tmp = put_user(rsp.length, &r->response.length);
	if (!ret)
		ret = tmp;

	tmp = put_user(status, &r->status);
	if (!ret)
		ret = tmp;

	// cleanup
	kfree(spec.payload);
	kfree(rsp.pointer);

	return ret;
}

static long ssam_dbg_if_getversion(struct file *file, unsigned long arg)
{
	put_user(SSAM_DBG_IF_VERSION, (u32 __user *)arg);
	return 0;
}

static long ssam_dbg_device_ioctl(struct file *file, unsigned int cmd,
				    unsigned long arg)
{
	switch (cmd) {
	case SSAM_DBG_IOCTL_GETVERSION:
		return ssam_dbg_if_getversion(file, arg);

	case SSAM_DBG_IOCTL_REQUEST:
		return ssam_dbg_if_request(file, arg);

	default:
		return -ENOIOCTLCMD;
	}
}

const struct file_operations ssam_dbg_device_fops = {
	.owner          = THIS_MODULE,
	.open           = ssam_dbg_device_open,
	.unlocked_ioctl = ssam_dbg_device_ioctl,
	.compat_ioctl   = ssam_dbg_device_ioctl,
	.llseek         = noop_llseek,
};

static int ssam_dbg_device_probe(struct platform_device *pdev)
{
	struct ssam_dbg_data *data;
	struct ssam_controller *ctrl;
	int status;

	status = ssam_client_bind(&pdev->dev, &ctrl);
	if (status)
		return status == -ENXIO ? -EPROBE_DEFER : status;

	data = devm_kzalloc(&pdev->dev, sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->ctrl = ctrl;

	data->dentry_dir = debugfs_create_dir("surface_aggregator", NULL);
	if (IS_ERR(data->dentry_dir))
		return PTR_ERR(data->dentry_dir);

	data->dentry_dev = debugfs_create_file("controller", 0600,
					       data->dentry_dir, data,
					       &ssam_dbg_device_fops);
	if (IS_ERR(data->dentry_dev)) {
		debugfs_remove(data->dentry_dir);
		return PTR_ERR(data->dentry_dev);
	}

	platform_set_drvdata(pdev, data);
	return 0;
}

static int ssam_dbg_device_remove(struct platform_device *pdev)
{
	struct ssam_dbg_data *data = platform_get_drvdata(pdev);

	debugfs_remove(data->dentry_dev);
	debugfs_remove(data->dentry_dir);

	return 0;
}

static void ssam_dbg_device_release(struct device *dev)
{
	// nothing to do
}

static struct platform_device ssam_dbg_device = {
	.name = SSAM_DBG_DEVICE_NAME,
	.id = PLATFORM_DEVID_NONE,
	.dev.release = ssam_dbg_device_release,
};

static struct platform_driver ssam_dbg_driver = {
	.probe = ssam_dbg_device_probe,
	.remove = ssam_dbg_device_remove,
	.driver = {
		.name = SSAM_DBG_DEVICE_NAME,
	},
};

static int __init ssam_debug_init(void)
{
	int status;

	status = platform_device_register(&ssam_dbg_device);
	if (status)
		return status;

	status = platform_driver_register(&ssam_dbg_driver);
	if (status)
		platform_device_unregister(&ssam_dbg_device);

	return status;
}
module_init(ssam_debug_init);

static void __exit ssam_debug_exit(void)
{
	platform_driver_unregister(&ssam_dbg_driver);
	platform_device_unregister(&ssam_dbg_device);
}
module_exit(ssam_debug_exit);

MODULE_AUTHOR("Maximilian Luz <luzmaximilian@gmail.com>");
MODULE_DESCRIPTION("DebugFS interface for Surface System Aggregator Module");
MODULE_LICENSE("GPL");
