/*
 * spi-hid-bus.c
 *
 * Copyright (c) 2020 Microsoft Corporation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

#include "spi-hid-bus.h"

#include <linux/spi/spi.h>

#define CREATE_TRACE_POINTS
#include "spi-hid_trace.h"

/* - Concurrency and ownership -
 * This file implements the bus transactions as sequences of asyncronous
 * spi transfers. That implies that different irq handlers and threads may
 * execute code in this file concurrently.
 * The spi_hid_bus struct is mainly protected from data races in two ways,
 * the .lock spinlock and an abstract token, the struct members should only be
 * accessed internally from this file.
 *
 * The spinlock is grabbed using the usual spin_lock/unlock functions and
 * protects the flags and the current back input. The context holding the
 * spin lock owns said members. It should only be held for short durations
 * and not across async boundaries.
 *
 * The token is grabbed by setting the token flag. As the flags are owned
 * by the spinlock, the spinlock is required to take/return the token.
 * The context holding the token owns the current front input and output.
 * The token is transferred on spi_async calls to the spi_async callback.
 *
 * The ownership rules also implies that in order to swap the input and output
 * buffers, both the spinlock and token are required.
 *
 * .client is implied immutable, mutability by the client requires that all
 * possible concurrent accesses are prevented - irqs calling _input blocked,
 * calls to _output blocked and ongoing transactions finished (by calling stop
 * and waiting for the stop error callback). This is also required to destroy
 * a spi_hid_bus instance.
 */

static int spi_hid_bus_input_transaction(struct spi_hid_bus *bus,
		u8 *buf, u16 length, void (*callback)(void *));
static void spi_hid_bus_input_begin(struct spi_hid_bus *bus);
static void spi_hid_bus_header_done_callback(void *context);
static void spi_hid_bus_input_done_callback(void *context);
static void spi_hid_bus_input_error(struct spi_hid_bus *bus,
		int error, int cause);

static void spi_hid_bus_output_begin(struct spi_hid_bus *bus);
static void spi_hid_bus_output_done_callback(void *context);
static void spi_hid_bus_output_error(struct spi_hid_bus *bus,
		int error, int cause);

void spi_hid_bus_input(struct spi_hid_bus *bus, u32 input_register,
		struct spi_hid_input_buf *buf, u16 buf_size)
{
	bus->input.buf = buf;
	bus->input.buf_size = buf_size;
	bus->input.reg = input_register;
	spi_hid_bus_input_begin(bus);
}

// Token is transferred from caller
static int spi_hid_bus_input_transaction(struct spi_hid_bus *bus,
		u8 *buf, u16 length, void (*callback)(void *))
{
	bus->input.transfer = (struct spi_transfer) {
		.tx_buf = buf,
		.rx_buf = buf,
		.len = length,
	};

	memset(buf, 0, length);

	spi_hid_read_approval(bus->input.reg, buf);

	spi_message_init_with_transfers(&bus->input.message,
			&bus->input.transfer, 1);

	bus->input.message.complete = callback;
	bus->input.message.context = bus;

	// If successful, token goes to callback, else back to caller
	return spi_async(bus->spi, &bus->input.message);
}

// Token is transferred from caller
static void spi_hid_bus_input_begin(struct spi_hid_bus *bus)
{
	int err;
	trace_spi_hid_bus_input_begin(&bus->spi->dev, 0);
	err = spi_hid_bus_input_transaction(bus,
			(u8 *)&bus->input.buf->header,
			sizeof(bus->input.buf->header),
			spi_hid_bus_header_done_callback); // <- token transferred to callback

	if (err) { // spi_async did not take token,
		dev_err(&bus->spi->dev, "spi bus error on async transfer: %d\n", err);
		spi_hid_bus_input_error(bus, SPI_HID_BUS_ERROR_SPI_QUEUE, err);
	} // token ransferred to _input_error
}

// Token is transferred from spi_async caller via spi driver
static void spi_hid_bus_header_done_callback(void *context)
{
	struct spi_hid_bus *bus = (struct spi_hid_bus *)(context);
	struct spi_hid_input_header header;
	u16 transfer_len;
	int err;

	if (bus->input.message.status) {
		dev_err(&bus->spi->dev, "Header spi transfer failed, status: %d\n",
				bus->input.message.status);
		spi_hid_bus_input_error(bus, SPI_HID_BUS_ERROR_SPI_STATUS,
				bus->input.message.status);
		return; // <- token has transferred to _input_error
	}

	spi_hid_input_header(bus->input.buf->header.header, &header);

	if (header.sync_const != SPI_HID_INPUT_HEADER_SYNC_BYTE) {
		dev_err(&bus->spi->dev,
				"Received wrong input report header sync constant (0x%x)\n",
				header.sync_const);
		spi_hid_bus_input_error(bus, SPI_HID_BUS_ERROR_SYNC_BYTE,
				header.sync_const);
		return; // <- token has transferred to _input_error
	}

	if (header.version != SPI_HID_INPUT_HEADER_VERSION) {
		dev_err(&bus->spi->dev,
				"Received unknown input report header version (v 0x%x)\n",
				header.version);
		spi_hid_bus_input_error(bus, SPI_HID_BUS_ERROR_VERSION, header.version);
		return; // <- token has transferred to _input_error
	}

	transfer_len = sizeof(spi_hid_read_approval_buf) + header.report_length;

	if (transfer_len > (bus->input.buf_size - sizeof(spi_hid_read_approval) - sizeof(spi_hid_input_header_buf))) {
		dev_err(&bus->spi->dev, "Received a too big input report (%d > %d)\n",
				transfer_len, bus->input.buf_size);
		spi_hid_bus_input_error(bus, SPI_HID_BUS_ERROR_BUF_SIZE, transfer_len);
		return; // <- token has transferred to _input_error
	}

	trace_spi_hid_bus_body_begin(&bus->spi->dev, 0, &header, transfer_len);

	err = spi_hid_bus_input_transaction(bus,
			(u8 *)&bus->input.buf->body, transfer_len,
			spi_hid_bus_input_done_callback); // <- transfer token to callback

	if (err) { // spi_async did not take token, we give it to input_error
		dev_err(&bus->spi->dev, "spi bus error on async transfer: %d\n", err);
		spi_hid_bus_input_error(bus, SPI_HID_BUS_ERROR_SPI_QUEUE, err);
	}
}

// Token is transferred from spi_async caller via spi driver
static void spi_hid_bus_input_done_callback(void *context)
{
	struct spi_hid_bus *bus = (struct spi_hid_bus *)(context);

	if (bus->input.message.status) {
		dev_err(&bus->spi->dev, "Body spi transfer failed, status: %d\n",
				bus->input.message.status);
		spi_hid_bus_input_error(bus, SPI_HID_BUS_ERROR_SPI_STATUS,
				bus->input.message.status);
		return;
	}

	trace_spi_hid_bus_input_done(&bus->spi->dev, 0);

	if (bus->client.input_callback)
		bus->client.input_callback(bus->client.context, bus->input.buf);
}

// Token is transferred from caller
static void spi_hid_bus_input_error(struct spi_hid_bus *bus,
		int error, int cause)
{
	trace_spi_hid_bus_input_error(&bus->spi->dev, 0, error, cause);

	if (bus->client.error_callback)
		bus->client.error_callback(bus->client.context, error, cause);
}

/* -- Output -- */

void spi_hid_bus_output(struct spi_hid_bus *bus,
		struct spi_hid_output_buf *buf, u16 length)
{
	bus->output.buf = buf;
	bus->output.length = length;
	spi_hid_bus_output_begin(bus);
}

// Token is transferred from caller
static void spi_hid_bus_output_begin(struct spi_hid_bus *bus)
{
	int err;
	trace_spi_hid_bus_output_begin(&bus->spi->dev, bus->output.length);

	bus->output.transfer = (struct spi_transfer) {
		.tx_buf = (u8 *)bus->output.buf,
		.rx_buf = (u8 *)bus->output.buf,
		.len = bus->output.length,
	};

	spi_message_init_with_transfers(&bus->output.message,
			&bus->output.transfer, 1);

	bus->output.message.complete = spi_hid_bus_output_done_callback;
	bus->output.message.context = bus;

	// If successful, token goes to callback, else back to caller
	err = spi_async(bus->spi, &bus->output.message);

	if (err) {
		dev_err(&bus->spi->dev, "spi bus error on async transfer: %d\n", err);
		spi_hid_bus_output_error(bus, SPI_HID_BUS_ERROR_SPI_QUEUE, err);
	} // <- Token transferred to output_error
}

// Token is transferred from caller
static void spi_hid_bus_output_done_callback(void *context)
{
	struct spi_hid_bus *bus = (struct spi_hid_bus *)(context);

	if (bus->output.message.status) {
		dev_err(&bus->spi->dev, "Output spi transfer failed, status: %d\n",
				bus->output.message.status);
		spi_hid_bus_output_error(bus, SPI_HID_BUS_ERROR_SPI_STATUS,
				bus->output.message.status);
		return; // <- Token transferred to output_error
	}

	trace_spi_hid_bus_output_done(&bus->spi->dev);
	if (bus->client.output_callback)
		bus->client.output_callback(bus->client.context, 0, 0);
}

// Token is transferred from caller
static void spi_hid_bus_output_error(struct spi_hid_bus *bus,
		int error, int cause)
{
	trace_spi_hid_bus_output_error(&bus->spi->dev, error, cause);

	if (bus->client.output_callback)
		bus->client.output_callback(bus->client.context, error, cause);
}

void spi_hid_bus_init(struct spi_hid_bus *bus, struct spi_device *spi)
{
	bus->spi = spi;
}
