// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/dma-mapping.h>
#include <linux/mei_cl_bus.h>
#include <linux/module.h>
#include <linux/mod_devicetable.h>

#include "context.h"
#include "control.h"
#include "data.h"
#include "receiver.h"

#define IPTS_MEI_UUID UUID_LE(0x3e8d0870, 0x271a, 0x4208, \
	0x8e, 0xb5, 0x9a, 0xcb, 0x94, 0x02, 0xae, 0x04)

static int ipts_init_probe(struct mei_cl_device *cldev,
		const struct mei_cl_device_id *id)
{
	int ret;
	struct ipts_context *ipts = NULL;

	dev_info(&cldev->dev, "Probing IPTS\n");

	// Setup the DMA bit mask
	if (!dma_coerce_mask_and_coherent(&cldev->dev, DMA_BIT_MASK(64))) {
		dev_info(&cldev->dev, "IPTS using DMA_BIT_MASK(64)\n");
	} else if (!dma_coerce_mask_and_coherent(&cldev->dev,
			DMA_BIT_MASK(32))) {
		dev_info(&cldev->dev, "IPTS using DMA_BIT_MASK(32)");
	} else {
		dev_err(&cldev->dev, "No suitable DMA for IPTS available\n");
		return -EFAULT;
	}

	ret = mei_cldev_enable(cldev);
	if (ret) {
		dev_err(&cldev->dev, "Cannot enable IPTS\n");
		return ret;
	}

	ipts = devm_kzalloc(&cldev->dev,
			sizeof(struct ipts_context), GFP_KERNEL);
	if (!ipts) {
		mei_cldev_disable(cldev);
		return -ENOMEM;
	}

	ipts->client_dev = cldev;
	ipts->dev = &cldev->dev;

	mei_cldev_set_drvdata(cldev, ipts);

	ipts->receiver_loop = kthread_run(ipts_receiver_loop, (void *)ipts,
			"ipts_receiver_loop");
	ipts->data_loop = kthread_run(ipts_data_loop, (void *)ipts,
			"ipts_data_loop");

	ipts_control_start(ipts);

	return 0;
}

static int ipts_init_remove(struct mei_cl_device *cldev)
{
	struct ipts_context *ipts = mei_cldev_get_drvdata(cldev);

	dev_info(&cldev->dev, "Removing IPTS\n");

	ipts_control_stop(ipts);
	mei_cldev_disable(cldev);
	kthread_stop(ipts->receiver_loop);
	kthread_stop(ipts->data_loop);

	return 0;
}

static struct mei_cl_device_id ipts_device_id[] = {
	{ "", IPTS_MEI_UUID, MEI_CL_VERSION_ANY },
	{ },
};
MODULE_DEVICE_TABLE(mei, ipts_device_id);

static struct mei_cl_driver ipts_driver = {
	.id_table = ipts_device_id,
	.name = "ipts",
	.probe = ipts_init_probe,
	.remove = ipts_init_remove,
};
module_mei_cl_driver(ipts_driver);

MODULE_DESCRIPTION("IPTS touchscreen driver");
MODULE_AUTHOR("Dorian Stoll <dorian.stoll@tmsp.io>");
MODULE_LICENSE("GPL");
