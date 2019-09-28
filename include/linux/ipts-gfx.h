/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 * Intel Precise Touch & Stylus
 * Copyright (c) 2016 Intel Corporation
 *
 */

#ifndef IPTS_GFX_H
#define IPTS_GFX_H

enum {
	IPTS_INTERFACE_V1 = 1,
};

#define IPTS_BUF_FLAG_CONTIGUOUS 0x01

#define IPTS_NOTIFY_STA_BACKLIGHT_OFF 0x00
#define IPTS_NOTIFY_STA_BACKLIGHT_ON  0x01

struct ipts_mapbuffer {
	u32 size;
	u32 flags;
	void *gfx_addr;
	void *cpu_addr;
	u64 buf_handle;
	u64 phy_addr;
};

struct ipts_wq_info {
	u64 db_addr;
	u64 db_phy_addr;
	u32 db_cookie_offset;
	u32 wq_size;
	u64 wq_addr;
	u64 wq_phy_addr;

	// head of wq is managed by GPU
	u64 wq_head_addr;
	u64 wq_head_phy_addr;

	// tail of wq is managed by CSME
	u64 wq_tail_addr;
	u64 wq_tail_phy_addr;
};

struct ipts_ops {
	int (*get_wq_info)(uint64_t gfx_handle,
		struct ipts_wq_info *wq_info);
	int (*map_buffer)(uint64_t gfx_handle,
		struct ipts_mapbuffer *mapbuffer);
	int (*unmap_buffer)(uint64_t gfx_handle, uint64_t buf_handle);
};

struct ipts_callback {
	void (*workload_complete)(void *data);
	void (*notify_gfx_status)(u32 status, void *data);
};

struct ipts_connect {
	// input: Client device for PM setup
	struct device *client;

	// input: Callback addresses
	struct ipts_callback ipts_cb;

	// input: Callback data
	void *data;

	// input: interface version
	u32 if_version;

	// output: GFX version
	u32 gfx_version;

	// output: GFX handle
	u64 gfx_handle;

	// output: GFX ops for IPTS
	struct ipts_ops ipts_ops;
};

int ipts_connect(struct ipts_connect *ipts_connect);
void ipts_disconnect(uint64_t gfx_handle);

#endif // IPTS_GFX_H
