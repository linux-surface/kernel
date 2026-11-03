// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2020-2023 Dorian Stoll
 *
 * Linux driver for Intel Precise Touch & Stylus
 */

#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/kref.h>
#include <linux/mei_cl_bus.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/stddef.h>
#include <linux/types.h>
#include <linux/wait.h>

#include "context.h"
#include "control.h"
#include "mei.h"
#include "receiver.h"
#include "spec-device.h"

/*
 * The MEI client ID for IPTS functionality.
 */
#define IPTS_ID UUID_LE(0x3e8d0870, 0x271a, 0x4208, 0x8e, 0xb5, 0x9a, 0xcb, 0x94, 0x02, 0xae, 0x04)

static int ipts_set_dma_mask(struct mei_cl_device *cldev)
{
	if (!cldev)
		return -EFAULT;

	if (!dma_coerce_mask_and_coherent(&cldev->dev, DMA_BIT_MASK(64)))
		return 0;

	return dma_coerce_mask_and_coherent(&cldev->dev, DMA_BIT_MASK(32));
}

void ipts_context_release(struct kref *refcount)
{
	struct ipts_context *ipts = container_of(refcount, struct ipts_context, refcount);
	struct mei_cl_device *cldev = ipts->mei.cldev;

	ipts_mei_free_messages(&ipts->mei);
	kfree(ipts);

	/*
	 * Drop the reference to the MEI device that probe took for the context.
	 */
	put_device(&cldev->dev);
}

static void ipts_context_drop_probe(void *data)
{
	struct ipts_context *ipts = data;

	kref_put(&ipts->refcount, ipts_context_release);
}

static int ipts_probe(struct mei_cl_device *cldev, const struct mei_cl_device_id *id)
{
	int ret = 0;
	struct ipts_context *ipts = NULL;

	if (!cldev)
		return -EFAULT;

	ret = ipts_set_dma_mask(cldev);
	if (ret) {
		dev_err(&cldev->dev, "Failed to set DMA mask for IPTS: %d\n", ret);
		return ret;
	}

	ret = mei_cldev_enable(cldev);
	if (ret) {
		dev_err(&cldev->dev, "Failed to enable MEI device: %d\n", ret);
		return ret;
	}

	/*
	 * The context is freed by its kref once every user dropped its reference. It must not be
	 * tied to the device lifetime: a receiver thread or HID device that is still there after
	 * a failed stop keeps using it after the device is gone.
	 */
	ipts = kzalloc(sizeof(*ipts), GFP_KERNEL);
	if (!ipts) {
		ret = -ENOMEM;
		goto err_disable;
	}

	/*
	 * Such a user also keeps sending through the MEI device and logging against it after
	 * remove returned, so the context holds a reference to it until it is freed.
	 */
	get_device(&cldev->dev);

	kref_init(&ipts->refcount);
	atomic_set(&ipts->users, 0);
	init_waitqueue_head(&ipts->users_wq);

	/*
	 * Before the release function can run: it frees the message list.
	 */
	ret = ipts_mei_init(&ipts->mei, cldev);
	if (ret) {
		dev_err(&cldev->dev, "Failed to init MEI bus logic: %d\n", ret);
		put_device(&cldev->dev);
		kfree(ipts);
		goto err_disable;
	}

	/*
	 * Drop the probe reference when the device is released. Remove and every later probe
	 * failure disable the MEI device before that, which cancels its receive callback, so no
	 * message arrives while the context is being freed. If adding the action fails, the
	 * context is freed at once, before the MEI device is disabled: the receive callback finds
	 * no context then, because drvdata is not set yet.
	 */
	ret = devm_add_action_or_reset(&cldev->dev, ipts_context_drop_probe, ipts);
	if (ret)
		goto err_disable;

	ipts->dev = &cldev->dev;
	ipts->mode = IPTS_MODE_EVENT;

	mutex_init(&ipts->feature_lock);
	init_completion(&ipts->feature_event);

	mei_cldev_set_drvdata(cldev, ipts);

	ret = ipts_control_start(ipts);
	if (ret) {
		dev_err(&cldev->dev, "Failed to start IPTS: %d\n", ret);
		goto err_disable;
	}

	return 0;

err_disable:
	mei_cldev_disable(cldev);
	return ret;
}

/*
 * How long ipts_remove() waits for the last user of the context to return. One that does not
 * return keeps the context alive, so it is never freed under it.
 */
#define IPTS_REMOVE_TIMEOUT_MS 12000

static void ipts_remove(struct mei_cl_device *cldev)
{
	int ret = 0;
	struct ipts_context *ipts = NULL;

	if (!cldev) {
		pr_err("MEI device is NULL!");
		return;
	}

	ipts = mei_cldev_get_drvdata(cldev);

	ret = ipts_control_stop(ipts);
	if (ret)
		dev_err(&cldev->dev, "Failed to stop IPTS: %d\n", ret);

	mei_cldev_disable(cldev);

	/*
	 * A failed stop keeps the receiver thread or the HID device, and their references, on
	 * purpose, so there is nothing to wait for.
	 */
	if (ret)
		return;

	/*
	 * Wait, bounded, for the remaining users of the context to return, so the module code is
	 * not freed while they still run it. That narrows the window, but does not close it: the
	 * last user wakes this from inside its own put, before it has left the module code. The
	 * probe reference is dropped by devres after this, and the context is freed after its
	 * last user.
	 */
	if (!wait_event_timeout(ipts->users_wq, atomic_read(&ipts->users) == 0,
				msecs_to_jiffies(IPTS_REMOVE_TIMEOUT_MS)))
		dev_err(&cldev->dev, "A user of the IPTS context did not return\n");
}

static struct mei_cl_device_id ipts_device_id_table[] = {
	{ .uuid = IPTS_ID, .version = MEI_CL_VERSION_ANY },
	{},
};
MODULE_DEVICE_TABLE(mei, ipts_device_id_table);

static struct mei_cl_driver ipts_driver = {
	.id_table = ipts_device_id_table,
	.name = "ipts",
	.probe = ipts_probe,
	.remove = ipts_remove,
};
module_mei_cl_driver(ipts_driver);

MODULE_DESCRIPTION("IPTS touchscreen driver");
MODULE_AUTHOR("Dorian Stoll <dorian.stoll@tmsp.io>");
MODULE_LICENSE("GPL");
