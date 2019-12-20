/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 * Intel Precise Touch & Stylus
 * Copyright (c) 2016 Intel Corporation
 *
 */

#ifndef _IPTS_H_
#define _IPTS_H_

#include <linux/hid.h>
#include <linux/ipts-binary.h>
#include <linux/ipts-gfx.h>
#include <linux/mei_cl_bus.h>
#include <linux/types.h>

#include "mei-msgs.h"
#include "state.h"

#define HID_PARALLEL_DATA_BUFFERS TOUCH_SENSOR_MAX_DATA_BUFFERS

#define IPTS_MAX_RETRY 3

struct ipts_buffer_info {
	char *addr;
	dma_addr_t dma_addr;
};

struct ipts_gfx_info {
	u64 gfx_handle;
	struct ipts_ops ipts_ops;
};

struct ipts_resource {
	// ME & GFX resource
	struct ipts_buffer_info touch_data_buffer_raw
		[HID_PARALLEL_DATA_BUFFERS];
	struct ipts_buffer_info touch_data_buffer_hid;
	struct ipts_buffer_info feedback_buffer[HID_PARALLEL_DATA_BUFFERS];
	struct ipts_buffer_info hid2me_buffer;
	u32 hid2me_buffer_size;

	u8 wq_item_size;
	struct ipts_wq_info wq_info;

	// ME2HID buffer
	char *me2hid_buffer;

	// GFX specific resource
	struct ipts_buffer_info raw_data_mode_output_buffer
		[HID_PARALLEL_DATA_BUFFERS][MAX_NUM_OUTPUT_BUFFERS];

	int num_of_outputs;
	bool default_resource_ready;
	bool raw_data_resource_ready;
};

struct ipts_info {
	struct mei_cl_device *cldev;
	struct hid_device *hid;

	struct work_struct init_work;
	struct work_struct raw_data_work;
	struct work_struct gfx_status_work;

	struct task_struct *event_loop;

#if IS_ENABLED(CONFIG_DEBUG_FS)
	struct dentry *dbgfs_dir;
#endif

	enum ipts_state state;

	enum touch_sensor_mode sensor_mode;
	struct touch_sensor_get_device_info_rsp_data device_info;
	struct ipts_resource resource;
	u8 hid_input_report[HID_MAX_BUFFER_SIZE];
	int num_of_parallel_data_buffers;
	bool hid_desc_ready;

	int current_buffer_index;
	int last_buffer_completed;
	int *last_submitted_id;

	struct ipts_gfx_info gfx_info;
	u64 kernel_handle;
	int gfx_status;
	bool display_status;

	bool restart;
};

#if IS_ENABLED(CONFIG_DEBUG_FS)
int ipts_dbgfs_register(struct ipts_info *ipts, const char *name);
void ipts_dbgfs_deregister(struct ipts_info *ipts);
#else
static int ipts_dbgfs_register(struct ipts_info *ipts, const char *name);
static void ipts_dbgfs_deregister(struct ipts_info *ipts);
#endif

void ipts_info(struct ipts_info *ipts, const char *fmt, ...);
void ipts_dbg(struct ipts_info *ipts, const char *fmt, ...);

// Because ipts_err is unconditional, this can stay a macro for now
#define ipts_err(ipts, format, arg...) \
	dev_err(&ipts->cldev->dev, format, ##arg)

/*
 * Inline functions
 */
static inline void ipts_set_state(struct ipts_info *ipts,
		enum ipts_state state)
{
	ipts->state = state;
}

static inline enum ipts_state ipts_get_state(const struct ipts_info *ipts)
{
	return ipts->state;
}

static inline bool ipts_is_default_resource_ready(const struct ipts_info *ipts)
{
	return ipts->resource.default_resource_ready;
}

static inline bool ipts_is_raw_data_resource_ready(const struct ipts_info *ipts)
{
	return ipts->resource.raw_data_resource_ready;
}

static inline struct ipts_buffer_info *ipts_get_feedback_buffer(
		struct ipts_info *ipts, int buffer_idx)
{
	return &ipts->resource.feedback_buffer[buffer_idx];
}

static inline struct ipts_buffer_info *ipts_get_touch_data_buffer_hid(
		struct ipts_info *ipts)
{
	return &ipts->resource.touch_data_buffer_hid;
}

static inline struct ipts_buffer_info *ipts_get_output_buffers_by_parallel_id(
		struct ipts_info *ipts, int parallel_idx)
{
	return &ipts->resource.raw_data_mode_output_buffer[parallel_idx][0];
}

static inline struct ipts_buffer_info *ipts_get_hid2me_buffer(
		struct ipts_info *ipts)
{
	return &ipts->resource.hid2me_buffer;
}

static inline void ipts_set_wq_item_size(struct ipts_info *ipts, u8 size)
{
	ipts->resource.wq_item_size = size;
}

static inline u8 ipts_get_wq_item_size(const struct ipts_info *ipts)
{
	return ipts->resource.wq_item_size;
}

static inline int ipts_get_num_of_parallel_buffers(const struct ipts_info *ipts)
{
	return ipts->num_of_parallel_data_buffers;
}

#endif // _IPTS_H_
