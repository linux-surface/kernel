/* SPDX-License-Identifier: GPL-2.0 */
/*
 * spi-hid_trace.h
 *
 * Copyright (c) 2020 Microsoft Corporation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM spi_hid

#if !defined(_SPI_HID_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _SPI_HID_TRACE_H

#include <linux/types.h>
#include <linux/tracepoint.h>
#include "spi-hid-core.h"

DECLARE_EVENT_CLASS(spi_hid_transfer,
	TP_PROTO(struct spi_hid *shid, const void *tx_buf, int tx_len,
			const void *rx_buf, u16 rx_len, int ret),

	TP_ARGS(shid, tx_buf, tx_len, rx_buf, rx_len, ret),

	TP_STRUCT__entry(
		__field(int, bus_num)
		__field(int, chip_select)
		__field(int, len)
		__field(int, ret)
		__dynamic_array(u8, rx_buf, rx_len)
		__dynamic_array(u8, tx_buf, tx_len)
	),

	TP_fast_assign(
		__entry->bus_num = shid->spi->controller->bus_num;
		__entry->chip_select = shid->spi->chip_select;
		__entry->len = rx_len + tx_len;
		__entry->ret = ret;

		memcpy(__get_dynamic_array(tx_buf), tx_buf, tx_len);
		memcpy(__get_dynamic_array(rx_buf), rx_buf, rx_len);
	),

	TP_printk("spi%d.%d: len=%d tx=[%*phD] rx=[%*phD] --> %d",
		__entry->bus_num, __entry->chip_select, __entry->len,
		__get_dynamic_array_len(tx_buf), __get_dynamic_array(tx_buf),
		__get_dynamic_array_len(rx_buf), __get_dynamic_array(rx_buf),
		__entry->ret)
);

DEFINE_EVENT(spi_hid_transfer, spi_hid_input_async,
	TP_PROTO(struct spi_hid *shid, const void *tx_buf, int tx_len,
			const void *rx_buf, u16 rx_len, int ret),
	TP_ARGS(shid, tx_buf, tx_len, rx_buf, rx_len, ret)
);

DEFINE_EVENT(spi_hid_transfer, spi_hid_input_header_complete,
	TP_PROTO(struct spi_hid *shid, const void *tx_buf, int tx_len,
			const void *rx_buf, u16 rx_len, int ret),
	TP_ARGS(shid, tx_buf, tx_len, rx_buf, rx_len, ret)
);

DEFINE_EVENT(spi_hid_transfer, spi_hid_input_body_complete,
	TP_PROTO(struct spi_hid *shid, const void *tx_buf, int tx_len,
			const void *rx_buf, u16 rx_len, int ret),
	TP_ARGS(shid, tx_buf, tx_len, rx_buf, rx_len, ret)
);

DEFINE_EVENT(spi_hid_transfer, spi_hid_output_begin,
	TP_PROTO(struct spi_hid *shid, const void *tx_buf, int tx_len,
			const void *rx_buf, u16 rx_len, int ret),
	TP_ARGS(shid, tx_buf, tx_len, rx_buf, rx_len, ret)
);

DEFINE_EVENT(spi_hid_transfer, spi_hid_output_end,
	TP_PROTO(struct spi_hid *shid, const void *tx_buf, int tx_len,
			const void *rx_buf, u16 rx_len, int ret),
	TP_ARGS(shid, tx_buf, tx_len, rx_buf, rx_len, ret)
);

DECLARE_EVENT_CLASS(spi_hid_irq,
	TP_PROTO(struct spi_hid *shid, int irq),

	TP_ARGS(shid, irq),

	TP_STRUCT__entry(
		__field(int, bus_num)
		__field(int, chip_select)
		__field(int, irq)
	),

	TP_fast_assign(
		__entry->bus_num = shid->spi->controller->bus_num;
		__entry->chip_select = shid->spi->chip_select;
		__entry->irq = irq;
	),

	TP_printk("spi%d.%d: IRQ %d",
		__entry->bus_num, __entry->chip_select, __entry->irq)
);

DEFINE_EVENT(spi_hid_irq, spi_hid_dev_irq,
	TP_PROTO(struct spi_hid *shid, int irq),
	TP_ARGS(shid, irq)
);

DECLARE_EVENT_CLASS(spi_hid,
	TP_PROTO(struct spi_hid *shid),

	TP_ARGS(shid),

	TP_STRUCT__entry(
		__field(int, bus_num)
		__field(int, chip_select)
		__field(int, input_stage)
		__field(int, power_state)
		__field(u32, input_transfer_pending)
		__field(bool, ready)

		__field(int, vendor_id)
		__field(int, product_id)
		__field(int, max_input_length)
		__field(int, max_output_length)
		__field(u16, hid_version)
		__field(u16, report_descriptor_length)
		__field(u16, version_id)
	),

	TP_fast_assign(
		__entry->bus_num = shid->spi->controller->bus_num;
		__entry->chip_select = shid->spi->chip_select;
		__entry->input_stage = shid->input_stage;
		__entry->power_state = shid->power_state;
		__entry->input_transfer_pending = shid->input_transfer_pending;
		__entry->ready = shid->ready;

		__entry->vendor_id = shid->desc.vendor_id;
		__entry->product_id = shid->desc.product_id;
		__entry->max_input_length = shid->desc.max_input_length;
		__entry->max_output_length = shid->desc.max_output_length;
		__entry->hid_version = shid->desc.hid_version;
		__entry->report_descriptor_length = shid->desc.report_descriptor_length;
		__entry->version_id = shid->desc.version_id;
	),

	TP_printk("spi%d.%d: (%04x:%04x v%d) HID v%d.%d state i:%d p:%d len i:%d o:%d r:%d flags %c:%d",
		__entry->bus_num, __entry->chip_select, __entry->vendor_id,
		__entry->product_id, __entry->version_id,
		__entry->hid_version >> 8, __entry->hid_version & 0xff,
		__entry->input_stage, __entry->power_state,
		__entry->max_input_length, __entry->max_output_length,
		__entry->report_descriptor_length,
		__entry->ready ? 'R' : 'r',
		__entry->input_transfer_pending)
);

DEFINE_EVENT(spi_hid, spi_hid_bus_input_report,
	TP_PROTO(struct spi_hid *shid),
	TP_ARGS(shid)
);

DEFINE_EVENT(spi_hid, spi_hid_process_input_report,
	TP_PROTO(struct spi_hid *shid),
	TP_ARGS(shid)
);

DEFINE_EVENT(spi_hid, spi_hid_input_report_handler,
	TP_PROTO(struct spi_hid *shid),
	TP_ARGS(shid)
);

DEFINE_EVENT(spi_hid, spi_hid_reset_work,
	TP_PROTO(struct spi_hid *shid),
	TP_ARGS(shid)
);

DEFINE_EVENT(spi_hid, spi_hid_create_device_work,
	TP_PROTO(struct spi_hid *shid),
	TP_ARGS(shid)
);

DEFINE_EVENT(spi_hid, spi_hid_refresh_device_work,
	TP_PROTO(struct spi_hid *shid),
	TP_ARGS(shid)
);

DEFINE_EVENT(spi_hid, spi_hid_response_handler,
	TP_PROTO(struct spi_hid *shid),
	TP_ARGS(shid)
);

#endif /* _SPI_HID_TRACE_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE spi-hid_trace
#include <trace/define_trace.h>
