// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/dma-mapping.h>

#include "context.h"

void ipts_resources_free(struct ipts_context *ipts)
{
	int i;
	u32 touch_buffer_size;
	u32 feedback_buffer_size;
	struct ipts_buffer_info *buffers;

	touch_buffer_size = ipts->device_info.data_size;
	feedback_buffer_size = ipts->device_info.feedback_size;

	buffers = ipts->data;
	for (i = 0; i < IPTS_BUFFERS; i++) {
		if (!buffers[i].address)
			continue;

		dmam_free_coherent(ipts->dev, touch_buffer_size,
				buffers[i].address, buffers[i].dma_address);

		buffers[i].address = NULL;
		buffers[i].dma_address = 0;
	}

	buffers = ipts->feedback;
	for (i = 0; i < IPTS_BUFFERS; i++) {
		if (!buffers[i].address)
			continue;

		dmam_free_coherent(ipts->dev, feedback_buffer_size,
				buffers[i].address, buffers[i].dma_address);

		buffers[i].address = NULL;
		buffers[i].dma_address = 0;
	}

	if (ipts->doorbell.address) {
		dmam_free_coherent(ipts->dev, sizeof(u32),
				ipts->doorbell.address,
				ipts->doorbell.dma_address);

		ipts->doorbell.address = NULL;
		ipts->doorbell.dma_address = 0;
	}

	if (ipts->workqueue.address) {
		dmam_free_coherent(ipts->dev, sizeof(u32),
				ipts->workqueue.address,
				ipts->workqueue.dma_address);

		ipts->workqueue.address = NULL;
		ipts->workqueue.dma_address = 0;
	}

	if (ipts->host2me.address) {
		dmam_free_coherent(ipts->dev, touch_buffer_size,
				ipts->host2me.address,
				ipts->host2me.dma_address);

		ipts->host2me.address = NULL;
		ipts->host2me.dma_address = 0;
	}
}

int ipts_resources_init(struct ipts_context *ipts)
{
	int i;
	u32 touch_buffer_size;
	u32 feedback_buffer_size;
	struct ipts_buffer_info *buffers;

	touch_buffer_size = ipts->device_info.data_size;
	feedback_buffer_size = ipts->device_info.feedback_size;

	buffers = ipts->data;
	for (i = 0; i < IPTS_BUFFERS; i++) {
		buffers[i].address = dmam_alloc_coherent(ipts->dev,
				touch_buffer_size,
				&buffers[i].dma_address,
				GFP_KERNEL);

		if (!buffers[i].address)
			goto release_resources;
	}

	buffers = ipts->feedback;
	for (i = 0; i < IPTS_BUFFERS; i++) {
		buffers[i].address = dmam_alloc_coherent(ipts->dev,
				feedback_buffer_size,
				&buffers[i].dma_address,
				GFP_KERNEL);

		if (!buffers[i].address)
			goto release_resources;
	}

	ipts->doorbell.address = dmam_alloc_coherent(ipts->dev,
			sizeof(u32),
			&ipts->doorbell.dma_address,
			GFP_KERNEL);

	if (!ipts->doorbell.address)
		goto release_resources;

	ipts->workqueue.address = dmam_alloc_coherent(ipts->dev,
			sizeof(u32),
			&ipts->workqueue.dma_address,
			GFP_KERNEL);

	if (!ipts->workqueue.address)
		goto release_resources;

	ipts->host2me.address = dmam_alloc_coherent(ipts->dev,
			touch_buffer_size,
			&ipts->host2me.dma_address,
			GFP_KERNEL);

	if (!ipts->workqueue.address)
		goto release_resources;

	return 0;

release_resources:

	dev_err(ipts->dev, "Failed to allocate buffers\n");
	ipts_resources_free(ipts);

	return -ENOMEM;
}
