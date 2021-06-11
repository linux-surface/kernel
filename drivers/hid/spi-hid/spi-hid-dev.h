/*
 * spi-hid-dev.h
 *
 * Copyright (c) 2020 Microsoft Corporation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

#ifndef SPI_HID_DEV_H
#define SPI_HID_DEV_H


#include "spi-hid-bus.h"
#include "spi-hid-device-descriptor.h"
#include "spi-hid-protocol.h"
#include "spi-hid-pool.h"

#include <linux/spi/spi.h> // spi_transfer, spi_message
#include <linux/spinlock.h> // spinlock_t and functions

/*
 * spi-hid-dev events which may occur on the event callback function.
 * The event callback function may be called in interupt thread context and
 * should not be blocked or run for a long time, it is adviced that all work
 * resulting from these events are executed on a separate work queue thread.
 * EVENT_NONE is a noop event, can be ignored
 * EVENT_ERROR indicates an error has occurred and the device should be reset.
 *   Client must ensure all fetched input reports are out of scope and reset
 *   the hardware which automatically reinitializes the device and bus.
 * EVENT_RESET indicates that the device has reset, either because an error has
 *   occurred, or as a result of a hard device reset (from init or error event).
 *   Client must ensure all fetched input reports are out of scope and indicate
 *   that it is ready to restart the driver by calling the _restart() function.
 * EVENT_READY indicates that the device is initialized and ready to generate
 *   input reports and receive output reports.
 * EVENT_INPUT_REPORT indicates that at least one unsolicited input report is
 *   available to be fetched by calling the _input_report() function.
 * EVENT_RESPONSE indicates that an output report response is available to be
 *   fetched by calling the _input_report() function. The response event is
 *   functionally equivialent to the input report event to the driver, but
 *   gives the client an opportunity to fetch unsolicited reports on a
 *   different thread to responses, with a higher priority if necessary to
 *   reduce potential input latency.
 * EVENT_WAKEUP indicates that an irq has arrived from a device in a sleep
 *   power state. The client is responsible for handling the irq and set device
 *   into an awake power state.
 */
#define SPI_HID_DEV_EVENT_NONE         0
#define SPI_HID_DEV_EVENT_ERROR        1
#define SPI_HID_DEV_EVENT_RESET        2
#define SPI_HID_DEV_EVENT_READY        3
#define SPI_HID_DEV_EVENT_INPUT_REPORT 4
#define SPI_HID_DEV_EVENT_RESPONSE     5
#define SPI_HID_DEV_EVENT_WAKEUP       6

#define SPI_HID_DEV_READY 0
#define SPI_HID_DEV_TRANSACTION_ONGOING 1
#define SPI_HID_DEV_ASLEEP 2
#define SPI_HID_DEV_WAKEUP 3
#define SPI_HID_DEV_IRQ_REQUESTED 4
#define SPI_HID_DEV_IN_D3 5

struct spi_hid_dev {
	struct spi_device *spi;
	struct spi_hid_bus bus;
	unsigned long flags;
	u16 hid_desc_addr;
	struct spi_hid_device_descriptor desc;
	struct work_struct buffer_alloc_work;
	wait_queue_head_t wait;
	struct {
		struct spi_hid_pool buf;
		void *init_buf;
	} input;
	struct {
		struct mutex lock;
		void *buf;
		int status;
		int err;
	} output;
	void (*event_callback)(void *context, int event);
	void *event_callback_context;
};

/* Read an incoming input report from the device.
 * Should be called from workqueue thread context, the client must ensure that
 * this function is not called again until report and its buffer reference has
 * gone out of scope.
 * Returns the number of pending input reports. */
int spi_hid_dev_get_input_report(struct spi_hid_dev *dev,
		struct spi_hid_input_report *report);

/* Read an incoming request response from the device.
 * Should be called from workqueue thread context, the client must ensure that
 * no further requests are made until report and its buffer reference has gone
 * out of scope.
 */
int spi_hid_dev_get_response(struct spi_hid_dev *dev,
		struct spi_hid_input_report *report);

/* Send and output report to the device.
 * Should be called from workqueue thread context, the client must ensure that
 * this function is not called concurrently.
 * Returns 0 on success, negative error on failure */
int spi_hid_dev_output_report(struct spi_hid_dev *dev, u32 output_register,
		struct spi_hid_output_report *report);

/* Quiesce the device and stop all activity, device should be considered
 * unready after return and may be destroyed when all associated buffers in
 * use have gone out of scope */
void spi_hid_dev_stop(struct spi_hid_dev *dev);

/* Start handling device events and initiate the startup procedure */
void spi_hid_dev_start(struct spi_hid_dev *dev);

/* Must be called as a response to a reset event. Doing so, the client confirms
 * that no dev buffer claimed in an input report is in use and the dev is free
 * to reallocate its buffers */
int spi_hid_dev_restart(struct spi_hid_dev *dev);

/* Signal to the dev whether the device is asleep or awake and whether
 * interrupts should generate a wakeup event or not. */
void spi_hid_dev_asleep(struct spi_hid_dev *dev);
void spi_hid_dev_awake(struct spi_hid_dev *dev);
int spi_hid_dev_is_asleep(struct spi_hid_dev *dev);
int spi_hid_dev_clear_wakeup(struct spi_hid_dev *dev);

/* Get the number of discarded input reports due to buffer overflow since
 * this or init was last called */
int spi_hid_dev_get_discarded(struct spi_hid_dev *dev);

int spi_hid_dev_init(struct spi_hid_dev *dev, struct spi_device *spi,
		u16 hid_descr_addr);

void spi_hid_dev_destroy(struct spi_hid_dev *dev);

#endif