/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 * Intel Precise Touch & Stylus
 * Copyright (c) 2016 Intel Corporation
 *
 */

#ifndef _IPTS_RESOURCE_H_
#define _IPTS_RESOURCE_H_

int ipts_allocate_default_resource(struct ipts_info *ipts);
void ipts_free_default_resource(struct ipts_info *ipts);
int ipts_allocate_raw_data_resource(struct ipts_info *ipts);
void ipts_free_raw_data_resource(struct ipts_info *ipts);

void ipts_get_set_mem_window_cmd_data(struct ipts_info *ipts,
		struct touch_sensor_set_mem_window_cmd_data *data);

void ipts_set_input_buffer(struct ipts_info *ipts, int parallel_idx,
		u8 *cpu_addr, u64 dma_addr);

void ipts_set_output_buffer(struct ipts_info *ipts, int parallel_idx,
		int output_idx, u8 *cpu_addr, u64 dma_addr);

#endif // _IPTS_RESOURCE_H_
