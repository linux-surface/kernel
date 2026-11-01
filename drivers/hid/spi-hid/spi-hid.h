/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 Microsoft Corporation
 * Copyright (c) 2026 Google LLC
 */

#ifndef SPI_HID_H
#define SPI_HID_H

#include <linux/spi/spi.h>
#include <linux/sysfs.h>

/**
 * enum spi_hid_protocol - HID over SPI protocol revision
 * @SPI_HID_PROTOCOL_V1: HID Over SPI Protocol Specification 1.0
 * @SPI_HID_PROTOCOL_DRAFT: Pre-1.0 draft revision of the protocol (input
 *	header version 2, device descriptor version 1.0), as used by the
 *	touchscreen digitizer of the Microsoft Surface Pro X.
 */
enum spi_hid_protocol {
	SPI_HID_PROTOCOL_V1,
	SPI_HID_PROTOCOL_DRAFT,
};

/* struct spi_hid_conf - Conf provided to the core */
struct spi_hid_conf {
	enum spi_hid_protocol protocol;
	u32 input_report_header_address;
	u32 input_report_body_address;
	u32 output_report_address;
	u32 device_descriptor_address;	/* draft protocol only */
	u8 read_opcode;
	u8 write_opcode;
};

/**
 * struct spihid_ops - Ops provided to the core
 * @power_up: do sequencing to power up the device
 * @power_down: do sequencing to power down the device
 * @assert_reset: do sequencing to assert the reset line
 * @deassert_reset: do sequencing to deassert the reset line
 * @sleep_minimal_reset_delay: minimal sleep delay during reset
 */
struct spihid_ops {
	int (*power_up)(struct spihid_ops *ops);
	int (*power_down)(struct spihid_ops *ops);
	int (*assert_reset)(struct spihid_ops *ops);
	int (*deassert_reset)(struct spihid_ops *ops);
	void (*sleep_minimal_reset_delay)(struct spihid_ops *ops);
};

int spi_hid_core_probe(struct spi_device *spi, struct spihid_ops *ops,
		       struct spi_hid_conf *conf);

void spi_hid_core_remove(struct spi_device *spi);

extern const struct attribute_group *spi_hid_groups[];
extern const struct dev_pm_ops spi_hid_core_pm;

#endif /* SPI_HID_H */
