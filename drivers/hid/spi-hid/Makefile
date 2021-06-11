#
# Copyright (c) 2020 Microsoft Corporation
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 as published by
# the Free Software Foundation.
#
# Makefile for the SPI input drivers
#

obj-$(CONFIG_SPI_HID)				+= spi-hid.o

CFLAGS_spi-hid-bus.o = -I$(src)

spi-hid-objs := spi-hid-core.o spi-hid-dev.o spi-hid-bus.o
