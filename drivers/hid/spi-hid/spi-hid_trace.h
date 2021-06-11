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

#include <linux/tracepoint.h>

struct spi_hid_input_header;
struct spi_hid_input_body;

DECLARE_EVENT_CLASS(spi_hid_basic_event_template,
	TP_PROTO(struct device *dev),
	TP_ARGS(dev),
	TP_STRUCT__entry(
		__string(	 dev, dev_name(dev))
	),
	TP_fast_assign(
		__assign_str(dev, dev_name(dev));
	),
  TP_printk("dev %s",
		__get_str(dev)
	)
);

DECLARE_EVENT_CLASS(spi_hid_input_event_template,
	TP_PROTO(struct device *dev, u8 buf),
	TP_ARGS(dev, buf),
	TP_STRUCT__entry(
		__string(	 dev, dev_name(dev))
		__field(	u8, buf)
	),
	TP_fast_assign(
		__assign_str(dev, dev_name(dev));
		__entry->buf = buf
	),
  TP_printk("dev %s buf %d",
		__get_str(dev),
		__entry->buf
	)
);

DEFINE_EVENT(spi_hid_input_event_template, spi_hid_bus_input_pending,
	TP_PROTO(struct device *dev, u8 buf),
	TP_ARGS(dev, buf)
);

DEFINE_EVENT(spi_hid_input_event_template, spi_hid_bus_input_begin,
	TP_PROTO(struct device *dev, u8 buf),
	TP_ARGS(dev, buf)
);

TRACE_EVENT(spi_hid_bus_body_begin,
	TP_PROTO(
		struct device *dev,
		u8 buf,
		struct spi_hid_input_header *header,
		u16 transfer_len
	),
	TP_ARGS(dev, buf, header, transfer_len),
	TP_STRUCT__entry(
		__string(	 dev, dev_name(dev))
		__field(	u8, buf)
		__field(	u8, version)
		__field(	u8, report_type)
		__field(	u8, fragment_id)
		__field(	u16, report_length)
		__field(	u16, sync_const)
		__field(	u16, transfer_len)
	),
	TP_fast_assign(
		__assign_str(dev, dev_name(dev));
		__entry->buf = buf;
		__entry->version = header->version;
		__entry->report_type = header->report_type;
		__entry->fragment_id = header->fragment_id;
		__entry->report_length = header->report_length;
		__entry->sync_const = header->sync_const;
		__entry->transfer_len = transfer_len;
	),
  TP_printk("dev %s buf %d ver %d type %d frag %d len %d syn %d t_len %d",
		__get_str(dev),
		__entry->buf,
		__entry->version,
		__entry->report_type,
		__entry->fragment_id,
		__entry->report_length,
		__entry->sync_const,
		__entry->transfer_len
	)
);

DEFINE_EVENT(spi_hid_input_event_template, spi_hid_bus_input_done,
	TP_PROTO(struct device *dev, u8 buf),
	TP_ARGS(dev, buf)
);

TRACE_EVENT(spi_hid_bus_input_error,
	TP_PROTO(struct device *dev, u8 buf, int error, int cause),
	TP_ARGS(dev, buf, error, cause),
	TP_STRUCT__entry(
		__string(	 dev, dev_name(dev))
		__field(	u8, buf)
		__field(	int, error)
		__field(	int, cause)
	),
	TP_fast_assign(
		__assign_str(dev, dev_name(dev));
		__entry->buf = buf;
		__entry->error = error;
		__entry->cause = cause;
	),
  TP_printk("dev %s buf %d err %d cause %d",
		__get_str(dev),
		__entry->buf,
		__entry->error,
		__entry->cause
	)
);

DEFINE_EVENT(spi_hid_basic_event_template, spi_hid_bus_output_pending,
	TP_PROTO(struct device *dev),
	TP_ARGS(dev)
);

TRACE_EVENT(spi_hid_bus_output_begin,
	TP_PROTO(struct device *dev, u16 len),
	TP_ARGS(dev, len),
	TP_STRUCT__entry(
		__string(	dev, dev_name(dev))
		__field(	u16, len)
	),
	TP_fast_assign(
		__assign_str(dev, dev_name(dev));
		__entry->len = len;
	),
	TP_printk("dev %s len",
		__get_str(dev),
		__entry->len
	)
);

DEFINE_EVENT(spi_hid_basic_event_template, spi_hid_bus_output_done,
	TP_PROTO(struct device *dev),
	TP_ARGS(dev)
);

TRACE_EVENT(spi_hid_bus_output_error,
	TP_PROTO(struct device *dev, int error, int cause),
	TP_ARGS(dev, error, cause),
	TP_STRUCT__entry(
		__string(	 dev, dev_name(dev))
		__field(	int, error)
		__field(	int, cause)
	),
	TP_fast_assign(
		__assign_str(dev, dev_name(dev));
		__entry->error = error;
		__entry->cause = cause;
	),
  TP_printk("dev %s err %d cause %d",
		__get_str(dev),
		__entry->error,
		__entry->cause
	)
);

DEFINE_EVENT(spi_hid_basic_event_template, spi_hid_bus_stop_pending,
	TP_PROTO(struct device *dev),
	TP_ARGS(dev)
);

DEFINE_EVENT(spi_hid_basic_event_template, spi_hid_bus_stop_event,
	TP_PROTO(struct device *dev),
	TP_ARGS(dev)
);

DEFINE_EVENT(spi_hid_basic_event_template, spi_hid_bus_reset,
	TP_PROTO(struct device *dev),
	TP_ARGS(dev)
);

#endif /* _SPI_HID_TRACE_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE spi-hid_trace
#include <trace/define_trace.h>