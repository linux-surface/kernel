/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 * Intel Precise Touch & Stylus
 * Copyright (c) 2016 Intel Corporation
 *
 */

#ifndef IPTS_BINARY_H
#define IPTS_BINARY_H

#include <linux/ipts.h>
#include <linux/types.h>

#define IPTS_BIN_HEADER_VERSION 2

#pragma pack(1)

// we support 16 output buffers (1:feedback, 15:HID)
#define  MAX_NUM_OUTPUT_BUFFERS 16

enum ipts_bin_res_type {
	IPTS_BIN_KERNEL,
	IPTS_BIN_RO_DATA,
	IPTS_BIN_RW_DATA,
	IPTS_BIN_SENSOR_FRAME,
	IPTS_BIN_OUTPUT,
	IPTS_BIN_DYNAMIC_STATE_HEAP,
	IPTS_BIN_PATCH_LOCATION_LIST,
	IPTS_BIN_ALLOCATION_LIST,
	IPTS_BIN_COMMAND_BUFFER_PACKET,
	IPTS_BIN_TAG,
};

struct ipts_bin_header {
	char str[4];
	u32 version;

#if IPTS_BIN_HEADER_VERSION > 1
	u32 gfxcore;
	u32 revid;
#endif
};

struct ipts_bin_alloc {
	u32 handle;
	u32 reserved;
};

struct ipts_bin_alloc_list {
	u32 num;
	struct ipts_bin_alloc alloc[];
};

struct ipts_bin_cmdbuf {
	u32 size;
	char data[];
};

struct ipts_bin_res {
	u32 handle;
	enum ipts_bin_res_type type;
	u32 initialize;
	u32 aligned_size;
	u32 size;
	char data[];
};

enum ipts_bin_io_buffer_type {
	IPTS_INPUT,
	IPTS_OUTPUT,
	IPTS_CONFIGURATION,
	IPTS_CALIBRATION,
	IPTS_FEATURE,
};

struct ipts_bin_io_header {
	char str[10];
	u16 type;
};

struct ipts_bin_res_list {
	u32 num;
	struct ipts_bin_res res[];
};

struct ipts_bin_patch {
	u32 index;
	u32 reserved1[2];
	u32 alloc_offset;
	u32 patch_offset;
	u32 reserved2;
};

struct ipts_bin_patch_list {
	u32 num;
	struct ipts_bin_patch patch[];
};

struct ipts_bin_guc_wq_info {
	u32 batch_offset;
	u32 size;
	char data[];
};

struct ipts_bin_bufid_patch {
	u32 imm_offset;
	u32 mem_offset;
};

enum ipts_bin_data_file_flags {
	IPTS_DATA_FILE_FLAG_NONE = 0,
	IPTS_DATA_FILE_FLAG_SHARE = 1,
	IPTS_DATA_FILE_FLAG_ALLOC_CONTIGUOUS = 2,
};

struct ipts_bin_data_file_info {
	u32 io_buffer_type;
	u32 flags;
	char file_name[MAX_IOCL_FILE_NAME_LEN];
};

struct ipts_bin_fw_info {
	char fw_name[MAX_IOCL_FILE_NAME_LEN];

	// output index. -1 for no use
	s32 vendor_output;

	u32 num_of_data_files;
	struct ipts_bin_data_file_info data_file[];
};

struct ipts_bin_fw_list {
	u32 num_of_fws;
	struct ipts_bin_fw_info fw_info[];
};

#pragma pack()

#endif // IPTS_BINARY_H
