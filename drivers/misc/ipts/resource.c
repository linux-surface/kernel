// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 * Intel Precise Touch & Stylus
 * Copyright (c) 2016 Intel Corporation
 *
 */

#include <linux/dma-mapping.h>

#include "ipts.h"
#include "kernel.h"
#include "mei-msgs.h"

static void free_common_resource(struct ipts_info *ipts)
{
	char *addr;
	struct ipts_buffer_info *feedback_buffer;
	dma_addr_t dma_addr;
	u32 buffer_size;
	int i, num_of_parallels;

	if (ipts->resource.me2hid_buffer) {
		devm_kfree(&ipts->cldev->dev, ipts->resource.me2hid_buffer);
		ipts->resource.me2hid_buffer = 0;
	}

	addr = ipts->resource.hid2me_buffer.addr;
	dma_addr = ipts->resource.hid2me_buffer.dma_addr;
	buffer_size = ipts->resource.hid2me_buffer_size;

	if (ipts->resource.hid2me_buffer.addr) {
		dmam_free_coherent(&ipts->cldev->dev, buffer_size,
			addr, dma_addr);

		ipts->resource.hid2me_buffer.addr = 0;
		ipts->resource.hid2me_buffer.dma_addr = 0;
		ipts->resource.hid2me_buffer_size = 0;
	}

	feedback_buffer = ipts->resource.feedback_buffer;
	num_of_parallels = ipts_get_num_of_parallel_buffers(ipts);
	for (i = 0; i < num_of_parallels; i++) {

		if (!feedback_buffer[i].addr)
			continue;

		dmam_free_coherent(&ipts->cldev->dev,
			ipts->device_info.feedback_size,
			feedback_buffer[i].addr, feedback_buffer[i].dma_addr);

		feedback_buffer[i].addr = 0;
		feedback_buffer[i].dma_addr = 0;
	}
}

static int allocate_common_resource(struct ipts_info *ipts)
{
	char *addr, *me2hid_addr;
	struct ipts_buffer_info *feedback_buffer;
	dma_addr_t dma_addr;
	int i, ret = 0, num_of_parallels;
	u32 buffer_size;

	buffer_size = ipts->device_info.feedback_size;

	addr = dmam_alloc_coherent(&ipts->cldev->dev, buffer_size, &dma_addr,
		GFP_ATOMIC | __GFP_ZERO);
	if (addr == NULL)
		return -ENOMEM;

	me2hid_addr = devm_kzalloc(&ipts->cldev->dev, buffer_size, GFP_KERNEL);
	if (me2hid_addr == NULL) {
		ret = -ENOMEM;
		goto release_resource;
	}

	ipts->resource.hid2me_buffer.addr = addr;
	ipts->resource.hid2me_buffer.dma_addr = dma_addr;
	ipts->resource.hid2me_buffer_size = buffer_size;
	ipts->resource.me2hid_buffer = me2hid_addr;

	feedback_buffer = ipts->resource.feedback_buffer;
	num_of_parallels = ipts_get_num_of_parallel_buffers(ipts);

	for (i = 0; i < num_of_parallels; i++) {
		feedback_buffer[i].addr = dmam_alloc_coherent(&ipts->cldev->dev,
			ipts->device_info.feedback_size,
			&feedback_buffer[i].dma_addr, GFP_ATOMIC|__GFP_ZERO);

		if (feedback_buffer[i].addr == NULL) {
			ret = -ENOMEM;
			goto release_resource;
		}
	}

	return 0;

release_resource:
	free_common_resource(ipts);

	return ret;
}

void ipts_free_raw_data_resource(struct ipts_info *ipts)
{
	if (ipts_is_raw_data_resource_ready(ipts)) {
		ipts->resource.raw_data_resource_ready = false;
		ipts_release_kernels(ipts);
	}
}

static int allocate_hid_resource(struct ipts_info *ipts)
{
	struct ipts_buffer_info *buffer_hid;

	// hid mode uses only one touch data buffer
	buffer_hid = &ipts->resource.touch_data_buffer_hid;
	buffer_hid->addr = dmam_alloc_coherent(&ipts->cldev->dev,
		ipts->device_info.frame_size, &buffer_hid->dma_addr,
		GFP_ATOMIC|__GFP_ZERO);

	if (buffer_hid->addr == NULL)
		return -ENOMEM;

	return 0;
}

static void free_hid_resource(struct ipts_info *ipts)
{
	struct ipts_buffer_info *buffer_hid;

	buffer_hid = &ipts->resource.touch_data_buffer_hid;
	if (buffer_hid->addr) {
		dmam_free_coherent(&ipts->cldev->dev,
			ipts->device_info.frame_size,
			buffer_hid->addr, buffer_hid->dma_addr);

		buffer_hid->addr = 0;
		buffer_hid->dma_addr = 0;
	}
}

int ipts_allocate_default_resource(struct ipts_info *ipts)
{
	int ret;

	ret = allocate_common_resource(ipts);
	if (ret) {
		ipts_dbg(ipts, "cannot allocate common resource\n");
		return ret;
	}

	ret = allocate_hid_resource(ipts);
	if (ret) {
		ipts_dbg(ipts, "cannot allocate hid resource\n");
		free_common_resource(ipts);
		return ret;
	}

	ipts->resource.default_resource_ready = true;

	return 0;
}

void ipts_free_default_resource(struct ipts_info *ipts)
{
	if (ipts_is_default_resource_ready(ipts)) {
		ipts->resource.default_resource_ready = false;
		free_hid_resource(ipts);
		free_common_resource(ipts);
	}
}

int ipts_allocate_raw_data_resource(struct ipts_info *ipts)
{
	int ret = 0;

	ret = ipts_init_kernels(ipts);
	if (ret)
		return ret;

	ipts->resource.raw_data_resource_ready = true;
	return 0;
}

static void get_hid_only_smw_cmd_data(struct ipts_info *ipts,
		struct touch_sensor_set_mem_window_cmd_data *data,
		struct ipts_resource *resrc)
{
	struct ipts_buffer_info *touch_buf;
	struct ipts_buffer_info *feedback_buf;

	touch_buf = &resrc->touch_data_buffer_hid;
	feedback_buf = &resrc->feedback_buffer[0];

	data->touch_data_buffer_addr_lower[0] =
		lower_32_bits(touch_buf->dma_addr);

	data->touch_data_buffer_addr_upper[0] =
		upper_32_bits(touch_buf->dma_addr);

	data->feedback_buffer_addr_lower[0] =
		lower_32_bits(feedback_buf->dma_addr);

	data->feedback_buffer_addr_upper[0] =
		upper_32_bits(feedback_buf->dma_addr);
}

static void get_raw_data_only_smw_cmd_data(struct ipts_info *ipts,
		struct touch_sensor_set_mem_window_cmd_data *data,
		struct ipts_resource *resrc)
{
	u64 wq_tail_phy_addr;
	u64 cookie_phy_addr;
	struct ipts_buffer_info *touch_buf;
	struct ipts_buffer_info *feedback_buf;
	int i, num_of_parallels;

	touch_buf = resrc->touch_data_buffer_raw;
	feedback_buf = resrc->feedback_buffer;

	num_of_parallels = ipts_get_num_of_parallel_buffers(ipts);
	for (i = 0; i < num_of_parallels; i++) {
		data->touch_data_buffer_addr_lower[i] =
			lower_32_bits(touch_buf[i].dma_addr);

		data->touch_data_buffer_addr_upper[i] =
			upper_32_bits(touch_buf[i].dma_addr);

		data->feedback_buffer_addr_lower[i] =
			lower_32_bits(feedback_buf[i].dma_addr);

		data->feedback_buffer_addr_upper[i] =
			upper_32_bits(feedback_buf[i].dma_addr);
	}

	wq_tail_phy_addr = resrc->wq_info.wq_tail_phy_addr;
	data->tail_offset_addr_lower = lower_32_bits(wq_tail_phy_addr);
	data->tail_offset_addr_upper = upper_32_bits(wq_tail_phy_addr);

	cookie_phy_addr = resrc->wq_info.db_phy_addr +
		resrc->wq_info.db_cookie_offset;

	data->doorbell_cookie_addr_lower = lower_32_bits(cookie_phy_addr);
	data->doorbell_cookie_addr_upper = upper_32_bits(cookie_phy_addr);
	data->work_queue_size = resrc->wq_info.wq_size;
	data->work_queue_item_size = resrc->wq_item_size;
}

void ipts_get_set_mem_window_cmd_data(struct ipts_info *ipts,
		struct touch_sensor_set_mem_window_cmd_data *data)
{
	struct ipts_resource *resrc = &ipts->resource;

	if (ipts->sensor_mode == TOUCH_SENSOR_MODE_RAW_DATA)
		get_raw_data_only_smw_cmd_data(ipts, data, resrc);
	else if (ipts->sensor_mode == TOUCH_SENSOR_MODE_HID)
		get_hid_only_smw_cmd_data(ipts, data, resrc);

	// hid2me is common for "raw data" and "hid"
	data->hid2me_buffer_addr_lower =
		lower_32_bits(resrc->hid2me_buffer.dma_addr);

	data->hid2me_buffer_addr_upper =
		upper_32_bits(resrc->hid2me_buffer.dma_addr);

	data->hid2me_buffer_size = resrc->hid2me_buffer_size;
}

void ipts_set_input_buffer(struct ipts_info *ipts, int parallel_idx,
		u8 *cpu_addr, u64 dma_addr)
{
	struct ipts_buffer_info *touch_buf;

	touch_buf = ipts->resource.touch_data_buffer_raw;
	touch_buf[parallel_idx].dma_addr = dma_addr;
	touch_buf[parallel_idx].addr = cpu_addr;
}

void ipts_set_output_buffer(struct ipts_info *ipts, int parallel_idx,
		int output_idx, u8 *cpu_addr, u64 dma_addr)
{
	struct ipts_buffer_info *output_buf;

	output_buf = &ipts->resource.raw_data_mode_output_buffer
		[parallel_idx][output_idx];

	output_buf->dma_addr = dma_addr;
	output_buf->addr = cpu_addr;
}
