# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for the SPI HID input drivers
#
# Copyright (c) 2021 Microsoft Corporation
#

obj-$(CONFIG_SPI_HID_CORE)	+= spi-hid.o
spi-hid-objs 			= spi-hid-core.o
CFLAGS_spi-hid-core.o 		:= -I$(src)
obj-$(CONFIG_SPI_HID_ACPI)	+= spi-hid-acpi.o
obj-$(CONFIG_SPI_HID_OF)	+= spi-hid-of.o
