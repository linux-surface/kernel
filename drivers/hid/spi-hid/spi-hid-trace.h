/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 Microsoft Corporation
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
		__field(int, ret)
		__dynamic_array(u8, rx_buf, rx_len)
		__dynamic_array(u8, tx_buf, tx_len)
	),

	TP_fast_assign(
		__entry->bus_num = shid->spi->controller->bus_num;
		__entry->chip_select = spi_get_chipselect(shid->spi, 0);
		__entry->ret = ret;

		memcpy(__get_dynamic_array(tx_buf), tx_buf, tx_len);
		memcpy(__get_dynamic_array(rx_buf), rx_buf, rx_len);
	),

	TP_printk("spi%d.%d: len=%d tx=[%*phD] rx=[%*phD] --> %d",
		  __entry->bus_num, __entry->chip_select,
		  __get_dynamic_array_len(tx_buf) + __get_dynamic_array_len(rx_buf),
		  __get_dynamic_array_len(tx_buf), __get_dynamic_array(tx_buf),
		  __get_dynamic_array_len(rx_buf), __get_dynamic_array(rx_buf),
		  __entry->ret)
);

DEFINE_EVENT(spi_hid_transfer, spi_hid_input_sync,
	     TP_PROTO(struct spi_hid *shid, const void *tx_buf, int tx_len,
		      const void *rx_buf, u16 rx_len, int ret),
	     TP_ARGS(shid, tx_buf, tx_len, rx_buf, rx_len, ret));

DEFINE_EVENT(spi_hid_transfer, spi_hid_input_header_complete,
	     TP_PROTO(struct spi_hid *shid, const void *tx_buf, int tx_len,
		      const void *rx_buf, u16 rx_len, int ret),
	     TP_ARGS(shid, tx_buf, tx_len, rx_buf, rx_len, ret));

DEFINE_EVENT(spi_hid_transfer, spi_hid_input_body_complete,
	     TP_PROTO(struct spi_hid *shid, const void *tx_buf, int tx_len,
		      const void *rx_buf, u16 rx_len, int ret),
	     TP_ARGS(shid, tx_buf, tx_len, rx_buf, rx_len, ret));

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
		__entry->chip_select = spi_get_chipselect(shid->spi, 0);
		__entry->irq = irq;
	),

	TP_printk("spi%d.%d: IRQ %d",
		  __entry->bus_num, __entry->chip_select, __entry->irq)
);

DEFINE_EVENT(spi_hid_irq, spi_hid_dev_irq,
	     TP_PROTO(struct spi_hid *shid, int irq), TP_ARGS(shid, irq));

DECLARE_EVENT_CLASS(spi_hid,
	TP_PROTO(struct spi_hid *shid),

	TP_ARGS(shid),

	TP_STRUCT__entry(
		__field(int, bus_num)
		__field(int, chip_select)
		__field(int, power_state)
		__field(u32, flags)

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
		__entry->chip_select = spi_get_chipselect(shid->spi, 0);
		__entry->power_state = shid->power_state;
		__entry->flags = shid->flags;

		__entry->vendor_id = shid->desc.vendor_id;
		__entry->product_id = shid->desc.product_id;
		__entry->max_input_length = shid->desc.max_input_length;
		__entry->max_output_length = shid->desc.max_output_length;
		__entry->hid_version = shid->desc.hid_version;
		__entry->report_descriptor_length =
					shid->desc.report_descriptor_length;
		__entry->version_id = shid->desc.version_id;
	),

	TP_printk("spi%d.%d: (%04x:%04x v%d) HID v%d.%d state p:%d len i:%d o:%d r:%d flags 0x%08x",
		  __entry->bus_num, __entry->chip_select,
		  __entry->vendor_id, __entry->product_id, __entry->version_id,
		  __entry->hid_version >> 8, __entry->hid_version & 0xff,
		  __entry->power_state,	__entry->max_input_length,
		  __entry->max_output_length, __entry->report_descriptor_length,
		  __entry->flags)
);

DEFINE_EVENT(spi_hid, spi_hid_header_transfer, TP_PROTO(struct spi_hid *shid),
	     TP_ARGS(shid));

DEFINE_EVENT(spi_hid, spi_hid_process_input_report,
	     TP_PROTO(struct spi_hid *shid), TP_ARGS(shid));

DEFINE_EVENT(spi_hid, spi_hid_input_report_handler,
	     TP_PROTO(struct spi_hid *shid), TP_ARGS(shid));

DEFINE_EVENT(spi_hid, spi_hid_reset_response, TP_PROTO(struct spi_hid *shid),
	     TP_ARGS(shid));

DEFINE_EVENT(spi_hid, spi_hid_create_device, TP_PROTO(struct spi_hid *shid),
	     TP_ARGS(shid));

DEFINE_EVENT(spi_hid, spi_hid_refresh_device, TP_PROTO(struct spi_hid *shid),
	     TP_ARGS(shid));

DEFINE_EVENT(spi_hid, spi_hid_response_handler, TP_PROTO(struct spi_hid *shid),
	     TP_ARGS(shid));

DEFINE_EVENT(spi_hid, spi_hid_error_handler, TP_PROTO(struct spi_hid *shid),
	     TP_ARGS(shid));

#endif /* _SPI_HID_TRACE_H */

/*
 * The following must be outside the protection of the above #if block.
 */
#undef TRACE_INCLUDE_PATH
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_PATH .

/*
 * It is required that the TRACE_INCLUDE_FILE be the same
 * as this file without the ".h".
 */
#define TRACE_INCLUDE_FILE spi-hid-trace
#include <trace/define_trace.h>
