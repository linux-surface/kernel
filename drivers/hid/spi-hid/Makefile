#
# Copyright (c) 2020 Microsoft Corporation
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 as published by
# the Free Software Foundation.
#
# Makefile for the SPI input drivers
#
CFLAGS_trace.o = -I$(src)
obj-$(CONFIG_SPI_HID)	+= spi-hid.o
spi-hid-objs := spi-hid-core.o trace.o
