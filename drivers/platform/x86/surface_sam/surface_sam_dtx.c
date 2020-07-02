// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Detachment system (DTX) driver for Microsoft Surface Book 2.
 */

#include <linux/acpi.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/input.h>
#include <linux/ioctl.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/platform_device.h>

#include "surface_sam_ssh.h"


#define USB_VENDOR_ID_MICROSOFT				0x045e
#define USB_DEVICE_ID_MS_SURFACE_BASE_2_INTEGRATION	0x0922

// name copied from MS device manager
#define DTX_INPUT_NAME	"Microsoft Surface Base 2 Integration Device"


#define DTX_CMD_LATCH_LOCK				_IO(0x11, 0x01)
#define DTX_CMD_LATCH_UNLOCK				_IO(0x11, 0x02)
#define DTX_CMD_LATCH_REQUEST				_IO(0x11, 0x03)
#define DTX_CMD_LATCH_OPEN				_IO(0x11, 0x04)
#define DTX_CMD_GET_OPMODE				_IOR(0x11, 0x05, int)

#define SAM_RQST_DTX_TC					0x11
#define SAM_RQST_DTX_CID_LATCH_LOCK			0x06
#define SAM_RQST_DTX_CID_LATCH_UNLOCK			0x07
#define SAM_RQST_DTX_CID_LATCH_REQUEST			0x08
#define SAM_RQST_DTX_CID_LATCH_OPEN			0x09
#define SAM_RQST_DTX_CID_GET_OPMODE			0x0D

#define SAM_EVENT_DTX_CID_CONNECTION			0x0c
#define SAM_EVENT_DTX_CID_BUTTON			0x0e
#define SAM_EVENT_DTX_CID_ERROR				0x0f
#define SAM_EVENT_DTX_CID_LATCH_STATUS			0x11

#define DTX_OPMODE_TABLET				0x00
#define DTX_OPMODE_LAPTOP				0x01
#define DTX_OPMODE_STUDIO				0x02

#define DTX_LATCH_CLOSED				0x00
#define DTX_LATCH_OPENED				0x01


// Warning: This must always be a power of 2!
#define DTX_CLIENT_BUF_SIZE				16

#define DTX_CONNECT_OPMODE_DELAY			1000

#define DTX_ERR		KERN_ERR "surface_sam_dtx: "
#define DTX_WARN	KERN_WARNING "surface_sam_dtx: "


struct surface_dtx_event {
	u8 type;
	u8 code;
	u8 arg0;
	u8 arg1;
} __packed;

struct surface_dtx_dev {
	struct ssam_event_notifier notif;
	struct delayed_work opmode_work;
	wait_queue_head_t waitq;
	struct miscdevice mdev;
	spinlock_t client_lock;
	struct list_head client_list;
	struct mutex mutex;
	bool active;
	spinlock_t input_lock;
	struct input_dev *input_dev;
};

struct surface_dtx_client {
	struct list_head node;
	struct surface_dtx_dev *ddev;
	struct fasync_struct *fasync;
	spinlock_t buffer_lock;
	unsigned int buffer_head;
	unsigned int buffer_tail;
	struct surface_dtx_event buffer[DTX_CLIENT_BUF_SIZE];
};


static struct surface_dtx_dev surface_dtx_dev;


static int surface_sam_query_opmpde(void)
{
	u8 result_buf[1];
	int status;

	struct surface_sam_ssh_rqst rqst = {
		.tc  = SAM_RQST_DTX_TC,
		.cid = SAM_RQST_DTX_CID_GET_OPMODE,
		.iid = 0x00,
		.chn = 0x01,
		.snc = 0x01,
		.cdl = 0x00,
		.pld = NULL,
	};

	struct surface_sam_ssh_buf result = {
		.cap = 1,
		.len = 0,
		.data = result_buf,
	};

	status = surface_sam_ssh_rqst(&rqst, &result);
	if (status)
		return status;

	if (result.len != 1)
		return -EFAULT;

	return result.data[0];
}


static int dtx_cmd_simple(u8 cid)
{
	struct surface_sam_ssh_rqst rqst = {
		.tc  = SAM_RQST_DTX_TC,
		.cid = cid,
		.iid = 0x00,
		.chn = 0x01,
		.snc = 0x00,
		.cdl = 0x00,
		.pld = NULL,
	};

	return surface_sam_ssh_rqst(&rqst, NULL);
}

static int dtx_cmd_get_opmode(int __user *buf)
{
	int opmode;

	opmode = surface_sam_query_opmpde();
	if (opmode < 0)
		return opmode;

	if (put_user(opmode, buf))
		return -EACCES;

	return 0;
}


static int surface_dtx_open(struct inode *inode, struct file *file)
{
	struct surface_dtx_dev *ddev = container_of(file->private_data, struct surface_dtx_dev, mdev);
	struct surface_dtx_client *client;

	// initialize client
	client = kzalloc(sizeof(struct surface_dtx_client), GFP_KERNEL);
	if (!client)
		return -ENOMEM;

	spin_lock_init(&client->buffer_lock);
	client->buffer_head = 0;
	client->buffer_tail = 0;
	client->ddev = ddev;

	// attach client
	spin_lock(&ddev->client_lock);
	list_add_tail_rcu(&client->node, &ddev->client_list);
	spin_unlock(&ddev->client_lock);

	file->private_data = client;
	nonseekable_open(inode, file);

	return 0;
}

static int surface_dtx_release(struct inode *inode, struct file *file)
{
	struct surface_dtx_client *client = file->private_data;

	// detach client
	spin_lock(&client->ddev->client_lock);
	list_del_rcu(&client->node);
	spin_unlock(&client->ddev->client_lock);
	synchronize_rcu();

	kfree(client);
	file->private_data = NULL;

	return 0;
}

static ssize_t surface_dtx_read(struct file *file, char __user *buf, size_t count, loff_t *offs)
{
	struct surface_dtx_client *client = file->private_data;
	struct surface_dtx_dev *ddev = client->ddev;
	struct surface_dtx_event event;
	size_t read = 0;
	int status = 0;

	if (count != 0 && count < sizeof(struct surface_dtx_event))
		return -EINVAL;

	if (!ddev->active)
		return -ENODEV;

	// check availability
	if (client->buffer_head == client->buffer_tail) {
		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;

		status = wait_event_interruptible(ddev->waitq,
				client->buffer_head != client->buffer_tail ||
				!ddev->active);
		if (status)
			return status;

		if (!ddev->active)
			return -ENODEV;
	}

	// copy events one by one
	while (read + sizeof(struct surface_dtx_event) <= count) {
		spin_lock_irq(&client->buffer_lock);

		if (client->buffer_head == client->buffer_tail) {
			spin_unlock_irq(&client->buffer_lock);
			break;
		}

		// get one event
		event = client->buffer[client->buffer_tail];
		client->buffer_tail = (client->buffer_tail + 1) & (DTX_CLIENT_BUF_SIZE - 1);
		spin_unlock_irq(&client->buffer_lock);

		// copy to userspace
		if (copy_to_user(buf, &event, sizeof(struct surface_dtx_event)))
			return -EFAULT;

		read += sizeof(struct surface_dtx_event);
	}

	return read;
}

static __poll_t surface_dtx_poll(struct file *file, struct poll_table_struct *pt)
{
	struct surface_dtx_client *client = file->private_data;
	int mask;

	poll_wait(file, &client->ddev->waitq, pt);

	if (client->ddev->active)
		mask = EPOLLOUT | EPOLLWRNORM;
	else
		mask = EPOLLHUP | EPOLLERR;

	if (client->buffer_head != client->buffer_tail)
		mask |= EPOLLIN | EPOLLRDNORM;

	return mask;
}

static int surface_dtx_fasync(int fd, struct file *file, int on)
{
	struct surface_dtx_client *client = file->private_data;

	return fasync_helper(fd, file, on, &client->fasync);
}

static long surface_dtx_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct surface_dtx_client *client = file->private_data;
	struct surface_dtx_dev *ddev = client->ddev;
	int status;

	status = mutex_lock_interruptible(&ddev->mutex);
	if (status)
		return status;

	if (!ddev->active) {
		mutex_unlock(&ddev->mutex);
		return -ENODEV;
	}

	switch (cmd) {
	case DTX_CMD_LATCH_LOCK:
		status = dtx_cmd_simple(SAM_RQST_DTX_CID_LATCH_LOCK);
		break;

	case DTX_CMD_LATCH_UNLOCK:
		status = dtx_cmd_simple(SAM_RQST_DTX_CID_LATCH_UNLOCK);
		break;

	case DTX_CMD_LATCH_REQUEST:
		status = dtx_cmd_simple(SAM_RQST_DTX_CID_LATCH_REQUEST);
		break;

	case DTX_CMD_LATCH_OPEN:
		status = dtx_cmd_simple(SAM_RQST_DTX_CID_LATCH_OPEN);
		break;

	case DTX_CMD_GET_OPMODE:
		status = dtx_cmd_get_opmode((int __user *)arg);
		break;

	default:
		status = -EINVAL;
		break;
	}

	mutex_unlock(&ddev->mutex);
	return status;
}

static const struct file_operations surface_dtx_fops = {
	.owner          = THIS_MODULE,
	.open           = surface_dtx_open,
	.release        = surface_dtx_release,
	.read           = surface_dtx_read,
	.poll           = surface_dtx_poll,
	.fasync         = surface_dtx_fasync,
	.unlocked_ioctl = surface_dtx_ioctl,
	.llseek         = no_llseek,
};

static struct surface_dtx_dev surface_dtx_dev = {
	.mdev = {
		.minor = MISC_DYNAMIC_MINOR,
		.name = "surface_dtx",
		.fops = &surface_dtx_fops,
	},
	.client_lock = __SPIN_LOCK_UNLOCKED(),
	.input_lock = __SPIN_LOCK_UNLOCKED(),
	.mutex  = __MUTEX_INITIALIZER(surface_dtx_dev.mutex),
	.active = false,
};


static void surface_dtx_push_event(struct surface_dtx_dev *ddev, struct surface_dtx_event *event)
{
	struct surface_dtx_client *client;

	rcu_read_lock();
	list_for_each_entry_rcu(client, &ddev->client_list, node) {
		spin_lock(&client->buffer_lock);

		client->buffer[client->buffer_head++] = *event;
		client->buffer_head &= DTX_CLIENT_BUF_SIZE - 1;

		if (unlikely(client->buffer_head == client->buffer_tail)) {
			printk(DTX_WARN "event buffer overrun\n");
			client->buffer_tail = (client->buffer_tail + 1) & (DTX_CLIENT_BUF_SIZE - 1);
		}

		spin_unlock(&client->buffer_lock);

		kill_fasync(&client->fasync, SIGIO, POLL_IN);
	}
	rcu_read_unlock();

	wake_up_interruptible(&ddev->waitq);
}


static void surface_dtx_update_opmpde(struct surface_dtx_dev *ddev)
{
	struct surface_dtx_event event;
	int opmode;

	// get operation mode
	opmode = surface_sam_query_opmpde();
	if (opmode < 0)
		printk(DTX_ERR "EC request failed with error %d\n", opmode);

	// send DTX event
	event.type = 0x11;
	event.code = 0x0D;
	event.arg0 = opmode;
	event.arg1 = 0x00;

	surface_dtx_push_event(ddev, &event);

	// send SW_TABLET_MODE event
	spin_lock(&ddev->input_lock);
	input_report_switch(ddev->input_dev, SW_TABLET_MODE, opmode != DTX_OPMODE_LAPTOP);
	input_sync(ddev->input_dev);
	spin_unlock(&ddev->input_lock);
}

static void surface_dtx_opmode_workfn(struct work_struct *work)
{
	struct surface_dtx_dev *ddev = container_of(work, struct surface_dtx_dev, opmode_work.work);

	surface_dtx_update_opmpde(ddev);
}

static u32 surface_dtx_notification(struct ssam_notifier_block *nb, const struct ssam_event *in_event)
{
	struct surface_dtx_dev *ddev = container_of(nb, struct surface_dtx_dev, notif.base);
	struct surface_dtx_event event;
	unsigned long delay;

	switch (in_event->command_id) {
	case SAM_EVENT_DTX_CID_CONNECTION:
	case SAM_EVENT_DTX_CID_BUTTON:
	case SAM_EVENT_DTX_CID_ERROR:
	case SAM_EVENT_DTX_CID_LATCH_STATUS:
		if (in_event->length > 2) {
			printk(DTX_ERR "unexpected payload size (cid: %x, len: %u)\n",
			       in_event->command_id, in_event->length);
			return SSAM_NOTIF_HANDLED;
		}

		event.type = in_event->target_category;
		event.code = in_event->command_id;
		event.arg0 = in_event->length >= 1 ? in_event->data[0] : 0x00;
		event.arg1 = in_event->length >= 2 ? in_event->data[1] : 0x00;
		surface_dtx_push_event(ddev, &event);
		break;

	default:
		return 0;
	}

	// update device mode
	if (in_event->command_id == SAM_EVENT_DTX_CID_CONNECTION) {
		delay = event.arg0 ? DTX_CONNECT_OPMODE_DELAY : 0;
		schedule_delayed_work(&ddev->opmode_work, delay);
	}

	return SSAM_NOTIF_HANDLED;
}


static struct input_dev *surface_dtx_register_inputdev(struct platform_device *pdev)
{
	struct input_dev *input_dev;
	int status;

	input_dev = input_allocate_device();
	if (!input_dev)
		return ERR_PTR(-ENOMEM);

	input_dev->name = DTX_INPUT_NAME;
	input_dev->dev.parent = &pdev->dev;
	input_dev->id.bustype = BUS_VIRTUAL;
	input_dev->id.vendor  = USB_VENDOR_ID_MICROSOFT;
	input_dev->id.product = USB_DEVICE_ID_MS_SURFACE_BASE_2_INTEGRATION;

	input_set_capability(input_dev, EV_SW, SW_TABLET_MODE);

	status = surface_sam_query_opmpde();
	if (status < 0) {
		input_free_device(input_dev);
		return ERR_PTR(status);
	}

	input_report_switch(input_dev, SW_TABLET_MODE, status != DTX_OPMODE_LAPTOP);

	status = input_register_device(input_dev);
	if (status) {
		input_unregister_device(input_dev);
		return ERR_PTR(status);
	}

	return input_dev;
}


static int surface_sam_dtx_probe(struct platform_device *pdev)
{
	struct surface_dtx_dev *ddev = &surface_dtx_dev;
	struct input_dev *input_dev;
	int status;

	// link to ec
	status = surface_sam_ssh_consumer_register(&pdev->dev);
	if (status)
		return status == -ENXIO ? -EPROBE_DEFER : status;

	input_dev = surface_dtx_register_inputdev(pdev);
	if (IS_ERR(input_dev))
		return PTR_ERR(input_dev);

	// initialize device
	mutex_lock(&ddev->mutex);
	if (ddev->active) {
		mutex_unlock(&ddev->mutex);
		status = -ENODEV;
		goto err_register;
	}

	INIT_DELAYED_WORK(&ddev->opmode_work, surface_dtx_opmode_workfn);
	INIT_LIST_HEAD(&ddev->client_list);
	init_waitqueue_head(&ddev->waitq);
	ddev->active = true;
	ddev->input_dev = input_dev;
	mutex_unlock(&ddev->mutex);

	status = misc_register(&ddev->mdev);
	if (status)
		goto err_register;

	// set up events
	ddev->notif.base.priority = 1;
	ddev->notif.base.fn = surface_dtx_notification;
	ddev->notif.event.reg = SSAM_EVENT_REGISTRY_SAM;
	ddev->notif.event.id.target_category = SSAM_SSH_TC_BAS;
	ddev->notif.event.id.instance = 0;
	ddev->notif.event.flags = SSAM_EVENT_SEQUENCED;

	status = surface_sam_ssh_notifier_register(&ddev->notif);
	if (status)
		goto err_events_setup;

	return 0;

err_events_setup:
	misc_deregister(&ddev->mdev);
err_register:
	input_unregister_device(ddev->input_dev);
	return status;
}

static int surface_sam_dtx_remove(struct platform_device *pdev)
{
	struct surface_dtx_dev *ddev = &surface_dtx_dev;
	struct surface_dtx_client *client;

	mutex_lock(&ddev->mutex);
	if (!ddev->active) {
		mutex_unlock(&ddev->mutex);
		return 0;
	}

	// mark as inactive
	ddev->active = false;
	mutex_unlock(&ddev->mutex);

	// After this call we're guaranteed that no more input events will arive
	surface_sam_ssh_notifier_unregister(&ddev->notif);

	// wake up clients
	spin_lock(&ddev->client_lock);
	list_for_each_entry(client, &ddev->client_list, node) {
		kill_fasync(&client->fasync, SIGIO, POLL_HUP);
	}
	spin_unlock(&ddev->client_lock);

	wake_up_interruptible(&ddev->waitq);

	// unregister user-space devices
	input_unregister_device(ddev->input_dev);
	misc_deregister(&ddev->mdev);

	return 0;
}


static const struct acpi_device_id surface_sam_dtx_match[] = {
	{ "MSHW0133", 0 },
	{ },
};
MODULE_DEVICE_TABLE(acpi, surface_sam_dtx_match);

static struct platform_driver surface_sam_dtx = {
	.probe = surface_sam_dtx_probe,
	.remove = surface_sam_dtx_remove,
	.driver = {
		.name = "surface_sam_dtx",
		.acpi_match_table = surface_sam_dtx_match,
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};
module_platform_driver(surface_sam_dtx);

MODULE_AUTHOR("Maximilian Luz <luzmaximilian@gmail.com>");
MODULE_DESCRIPTION("Surface Detachment System (DTX) Driver for 5th Generation Surface Devices");
MODULE_LICENSE("GPL");
