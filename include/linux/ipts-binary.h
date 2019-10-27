/*
 *
 * Intel Precise Touch & Stylus binary spec
 * Copyright (c) 2016 Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 */

#ifndef _INTEL_IPTS_BINARY_H_
#define _INTEL_IPTS_BINARY_H_

#include <linux/ipts.h>
#include <linux/types.h>

#define IPTS_BIN_HEADER_VERSION 2

#pragma pack(1)

// we support 16 output buffers (1:feedback, 15:HID)
#define  MAX_NUM_OUTPUT_BUFFERS 16

typedef enum {
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
} ipts_bin_res_type_t;

typedef struct ipts_bin_header {
	char str[4];
	u32 version;

#if IPTS_BIN_HEADER_VERSION > 1
	u32 gfxcore;
	u32 revid;
#endif
} ipts_bin_header_t;

typedef struct ipts_bin_alloc {
	u32 handle;
	u32 reserved;
} ipts_bin_alloc_t;

typedef struct ipts_bin_alloc_list {
	u32 num;
	ipts_bin_alloc_t alloc[];
} ipts_bin_alloc_list_t;

typedef struct ipts_bin_cmdbuf {
	u32 size;
	char data[];
} ipts_bin_cmdbuf_t;

typedef struct ipts_bin_res {
	u32 handle;
	ipts_bin_res_type_t type;
	u32 initialize;
	u32 aligned_size;
	u32 size;
	char data[];
} ipts_bin_res_t;

typedef enum {
	IPTS_INPUT,
	IPTS_OUTPUT,
	IPTS_CONFIGURATION,
	IPTS_CALIBRATION,
	IPTS_FEATURE,
} ipts_bin_io_buffer_type_t;

typedef struct ipts_bin_io_header {
	char str[10];
	u16 type;
} ipts_bin_io_header_t;

typedef struct ipts_bin_res_list {
	u32 num;
	ipts_bin_res_t res[];
} ipts_bin_res_list_t;

typedef struct ipts_bin_patch {
	u32 index;
	u32 reserved1[2];
	u32 alloc_offset;
	u32 patch_offset;
	u32 reserved2;
} ipts_bin_patch_t;

typedef struct ipts_bin_patch_list {
	u32 num;
	ipts_bin_patch_t patch[];
} ipts_bin_patch_list_t;

typedef struct ipts_bin_guc_wq_info {
	u32 batch_offset;
	u32 size;
	char data[];
} ipts_bin_guc_wq_info_t;

typedef struct ipts_bin_bufid_patch {
	u32 imm_offset;
	u32 mem_offset;
} ipts_bin_bufid_patch_t;

typedef enum {
	IPTS_DATA_FILE_FLAG_NONE = 0,
	IPTS_DATA_FILE_FLAG_SHARE = 1,
	IPTS_DATA_FILE_FLAG_ALLOC_CONTIGUOUS = 2,
} ipts_bin_data_file_flags_t;

typedef struct ipts_bin_data_file_info {
	u32 io_buffer_type;
	u32 flags;
	char file_name[MAX_IOCL_FILE_NAME_LEN];
} ipts_bin_data_file_info_t;

typedef struct ipts_bin_fw_info {
	char fw_name[MAX_IOCL_FILE_NAME_LEN];
	s32 vendor_output;	// output index. -1 for no use
	u32 num_of_data_files;
	ipts_bin_data_file_info_t data_file[];
} ipts_bin_fw_info_t;

typedef struct ipts_bin_fw_list {
	u32 num_of_fws;
	ipts_bin_fw_info_t fw_info[];
} ipts_bin_fw_list_t;

#pragma pack()

#endif // _INTEL_IPTS_BINARY_H_
