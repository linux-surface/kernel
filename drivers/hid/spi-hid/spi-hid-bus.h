/*
 * spi-hid-bus.h
 *
 * Copyright (c) 2020 Microsoft Corporation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

#ifndef SPI_HID_BUS_H
#define SPI_HID_BUS_H

#include "spi-hid-protocol.h"

#include <linux/spi/spi.h>

#define SPI_HID_BUS_STOP             0
#define SPI_HID_BUS_ERROR_SPI_QUEUE  1
#define SPI_HID_BUS_ERROR_SPI_STATUS 2
#define SPI_HID_BUS_ERROR_SYNC_BYTE  3
#define SPI_HID_BUS_ERROR_VERSION    4
#define SPI_HID_BUS_ERROR_BUF_SIZE   5
#define SPI_HID_BUS_ERROR_RESET      6
#define SPI_HID_BUS_ERROR_STOP       7

struct spi_hid_bus {
	struct spi_device *spi;
	struct {
		u32 reg;
		u16 buf_size;
		struct spi_hid_input_buf *buf;
		struct spi_transfer transfer;
		struct spi_message message;
	} input;
	struct {
		u16 length;
		struct spi_hid_output_buf *buf;
		struct spi_transfer transfer;
		struct spi_message message;
	} output;
	struct spi_hid_bus_client {
		void *context;
		void (*input_callback)(void *context, struct spi_hid_input_buf *buf);
		void (*output_callback)(void *context, int status, int error);
		void (*error_callback)(void *context, int error, int cause);
	} client;
};
/**
 * client - client interface
 * The spi_hid_bus instance owner is expected to populate the client interface
 * before using the instance. It may supply an arbritary callback context which
 * will be supplied as an argument to the callback functions as well as the
 * callback functions. All callbacks may be run in irq context and may not
 * sleep.
 *
 * input_callback - called when an input transaction is finished, supplies the
 *   client context and input buffer supplied to _input with the read data.
 *   If a non-zero value is returned, pending transactions will not be
 *   initiated untill spi_hid_bus_continue or _reset has been called.
 * ouput_callback - called when an output transaction is finished, supplies the
 *   client context, an error status or 0 if sucessfull, and error cause.
 * stop_callback - called when the bus is succesfully stopped, i.e. after stop
 *   has been initiated and all pending transactions have finished.
 *   spi_hid_bus_continue or _reset must be called to start transactions again
 * error_callback - called when a transaction has failed for some reason. The
 *   error reason is supplied as error and a context dependent cause value.
 *   If a non-zero value is returned, pending transactions will not be
 *   initiated untill spi_hid_bus_continue or _reset has been called.
 */

/**
 * spi_hid_bus_input - initiate input report transaction
 * @bus: bus device from which to transfer the input report
 * @input_register: device register to read from (from device descriptor)
 * @buf: buffer to where the input report is read into
 * @buf_size: size of buf, the maximum report length that can be read
 *
 * The input report may or may not be read immediately, depending on whether
 * there are any already ongoing transactions. In either case the function will
 * initiate or queue the transaction and then return immediately.
 *
 * When the transaction is finished or in the case of error, the input_callback
 * or the error_callback registered on bus->client will be called respectively.
 *
 * Only a maximum of two input transactions may be active / queued concurrently,
 * the client is expected to ensure this. It is expected that the device IRQ
 * handler in the client will ensure this automatically as a device should not
 * reassert it's irq line until the at least the last input report header has
 * been read from the device.
 *
 * The function may be called from irq context, in fact is expected to only
 * be called from the device's irq handler.
 */
void spi_hid_bus_input(struct spi_hid_bus *bus, u32 input_register,
		struct spi_hid_input_buf *buf, u16 buf_size);

/**
 * spi_hid_bus_output - initiate output report transaction
 * @bus: bus device to which to transfer the output report
 * @buf: buffer holding the output report to be written
 * @length: the length of the output report
 *
 * The client is expected to construct the report header and body in the buf
 * according to the protocol before calling this function.
 *
 * The output report may or may not be written immediately, depending on whether
 * there are any already ongoing transactions. In either case the function will
 * initiate or queue the transaction and then return immediately.
 *
 * When the transaction is finished or in the case of error, the output_callback
 * or the error_callback registered on bus->client will be called respectively.
 *
 * Only one output transactions may be active / queued concurrently,
 * the client is expected to ensure this using some sort of mutex lock.
 *
 * The function may be called from irq context or sleepable context.
 */
void spi_hid_bus_output(struct spi_hid_bus *bus,
		struct spi_hid_output_buf *buf, u16 length);

/**
 * spi_hid_bus_init - initialize spi_hid_bus instance
 * @bus: spi_hid_bus instance to initialize
 *
 * This function must be called before the instance is used.
 */
void spi_hid_bus_init(struct spi_hid_bus *bus, struct spi_device *spi);



#endif