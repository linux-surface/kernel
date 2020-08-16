// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include <linux/surface_aggregator_module.h>

#define SSAM_DBGDEV_NAME	"surface_sam_dbgdev"
#define SSAM_DBGDEV_VERS	0x0100


struct ssam_dbgdev_request {
	__u8 target_category;
	__u8 command_id;
	__u8 instance_id;
	__u8 channel;
	__u16 flags;
	__s16 status;

	struct {
		__u8 __pad[6];
		__u16 length;
		const __u8 __user *data;
	} payload;

	struct {
		__u8 __pad[6];
		__u16 length;
		__u8 __user *data;
	} response;
};

#define SSAM_DBGDEV_IOCTL_GETVERSION  _IOR(0xA5, 0, __u32)
#define SSAM_DBGDEV_IOCTL_REQUEST     _IOWR(0xA5, 1, struct ssam_dbgdev_request)


struct ssam_dbgdev {
	struct ssam_controller *ctrl;
	struct dentry *dentry_dir;
	struct dentry *dentry_dev;
};


static int ssam_dbgdev_open(struct inode *inode, struct file *filp)
{
	filp->private_data = inode->i_private;
	return nonseekable_open(inode, filp);
}

static long ssam_dbgdev_request(struct file *file, unsigned long arg)
{
	struct ssam_dbgdev *ddev = file->private_data;
	struct ssam_dbgdev_request __user *r;
	struct ssam_dbgdev_request rqst;
	struct ssam_request spec;
	struct ssam_response rsp;
	u8 *pldbuf = NULL;
	u8 *rspbuf = NULL;
	int status = 0, ret = 0, tmp;

	r = (struct ssam_dbgdev_request __user *)arg;
	ret = copy_struct_from_user(&rqst, sizeof(rqst), r, sizeof(*r));
	if (ret)
		goto out;

	// setup basic request fields
	spec.target_category = rqst.target_category;
	spec.command_id = rqst.command_id;
	spec.instance_id = rqst.instance_id;
	spec.channel = rqst.channel;
	spec.flags = rqst.flags;
	spec.length = rqst.payload.length;

	rsp.capacity = rqst.response.length;
	rsp.length = 0;

	// get request payload from user-space
	if (spec.length) {
		if (!rqst.payload.data) {
			ret = -EINVAL;
			goto out;
		}

		pldbuf = kzalloc(spec.length, GFP_KERNEL);
		if (!pldbuf) {
			status = -ENOMEM;
			ret = -EFAULT;
			goto out;
		}

		if (copy_from_user(pldbuf, rqst.payload.data, spec.length)) {
			ret = -EFAULT;
			goto out;
		}
	}
	spec.payload = pldbuf;

	// allocate response buffer
	if (rsp.capacity) {
		if (!rqst.response.data) {
			ret = -EINVAL;
			goto out;
		}

		rspbuf = kzalloc(rsp.capacity, GFP_KERNEL);
		if (!rspbuf) {
			status = -ENOMEM;
			ret = -EFAULT;
			goto out;
		}
	}
	rsp.pointer = rspbuf;

	// perform request
	status = ssam_request_sync(ddev->ctrl, &spec, &rsp);
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
	if (pldbuf)
		kfree(pldbuf);

	if (rspbuf)
		kfree(rspbuf);

	return ret;
}

static long ssam_dbgdev_getversion(struct file *file, unsigned long arg)
{
	put_user(SSAM_DBGDEV_VERS, (u32 __user *)arg);
	return 0;
}

static long ssam_dbgdev_ioctl(struct file *file, unsigned int cmd,
			      unsigned long arg)
{
	switch (cmd) {
	case SSAM_DBGDEV_IOCTL_GETVERSION:
		return ssam_dbgdev_getversion(file, arg);

	case SSAM_DBGDEV_IOCTL_REQUEST:
		return ssam_dbgdev_request(file, arg);

	default:
		return -EINVAL;
	}
}

const struct file_operations ssam_dbgdev_fops = {
	.owner          = THIS_MODULE,
	.open           = ssam_dbgdev_open,
	.unlocked_ioctl = ssam_dbgdev_ioctl,
	.compat_ioctl   = ssam_dbgdev_ioctl,
	.llseek         = noop_llseek,
};

static int ssam_dbgdev_probe(struct platform_device *pdev)
{
	struct ssam_dbgdev *ddev;
	struct ssam_controller *ctrl;
	int status;

	status = ssam_client_bind(&pdev->dev, &ctrl);
	if (status)
		return status == -ENXIO ? -EPROBE_DEFER : status;

	ddev = devm_kzalloc(&pdev->dev, sizeof(struct ssam_dbgdev), GFP_KERNEL);
	if (!ddev)
		return -ENOMEM;

	ddev->ctrl = ctrl;

	ddev->dentry_dir = debugfs_create_dir("surface_sam", NULL);
	if (IS_ERR(ddev->dentry_dir))
		return PTR_ERR(ddev->dentry_dir);

	ddev->dentry_dev = debugfs_create_file("controller", 0600,
					       ddev->dentry_dir, ddev,
					       &ssam_dbgdev_fops);
	if (IS_ERR(ddev->dentry_dev)) {
		debugfs_remove(ddev->dentry_dir);
		return PTR_ERR(ddev->dentry_dev);
	}

	platform_set_drvdata(pdev, ddev);
	return 0;
}

static int ssam_dbgdev_remove(struct platform_device *pdev)
{
	struct ssam_dbgdev *ddev = platform_get_drvdata(pdev);

	debugfs_remove(ddev->dentry_dev);
	debugfs_remove(ddev->dentry_dir);

	platform_set_drvdata(pdev, NULL);
	return 0;
}

static void ssam_dbgdev_release(struct device *dev)
{
	// nothing to do
}


static struct platform_device ssam_dbgdev_device = {
	.name = SSAM_DBGDEV_NAME,
	.id = PLATFORM_DEVID_NONE,
	.dev.release = ssam_dbgdev_release,
};

static struct platform_driver ssam_dbgdev_driver = {
	.probe 	= ssam_dbgdev_probe,
	.remove = ssam_dbgdev_remove,
	.driver = {
		.name = SSAM_DBGDEV_NAME,
	},
};

static int __init surface_sam_debugfs_init(void)
{
	int status;

	status = platform_device_register(&ssam_dbgdev_device);
	if (status)
		return status;

	status = platform_driver_register(&ssam_dbgdev_driver);
	if (status)
		platform_device_unregister(&ssam_dbgdev_device);

	return status;
}

static void __exit surface_sam_debugfs_exit(void)
{
	platform_driver_unregister(&ssam_dbgdev_driver);
	platform_device_unregister(&ssam_dbgdev_device);
}

module_init(surface_sam_debugfs_init);
module_exit(surface_sam_debugfs_exit);

MODULE_AUTHOR("Maximilian Luz <luzmaximilian@gmail.com>");
MODULE_DESCRIPTION("DebugFS entries for Surface Aggregator Module");
MODULE_LICENSE("GPL");
