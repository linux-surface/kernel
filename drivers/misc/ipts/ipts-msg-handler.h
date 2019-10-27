/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 * Intel Precise Touch & Stylus
 * Copyright (c) 2016 Intel Corporation
 *
 */

#ifndef _IPTS_MSG_HANDLER_H_
#define _IPTS_MSG_HANDLER_H_

int ipts_start(struct ipts_info *ipts);
void ipts_stop(struct ipts_info *ipts);
int ipts_handle_cmd(struct ipts_info *ipts, u32 cmd, void *data, int data_size);

int ipts_handle_resp(struct ipts_info *ipts,
		struct touch_sensor_msg_m2h *m2h_msg, u32 msg_len);

int ipts_send_feedback(struct ipts_info *ipts,
		int buffer_idx, u32 transaction_id);

int ipts_handle_processed_data(struct ipts_info *ipts);
int ipts_send_sensor_quiesce_io_cmd(struct ipts_info *ipts);
int ipts_send_sensor_hid_ready_for_data_cmd(struct ipts_info *ipts);
int ipts_send_sensor_clear_mem_window_cmd(struct ipts_info *ipts);
int ipts_restart(struct ipts_info *ipts);

#endif /* _IPTS_MSG_HANDLER_H */
