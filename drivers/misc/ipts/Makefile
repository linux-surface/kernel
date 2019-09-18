# SPDX-License-Identifier: GPL-2.0-or-later
#
# Makefile - Intel Precise Touch & Stylus device driver
# Copyright (c) 2016 Intel Corporation
#

obj-$(CONFIG_INTEL_IPTS)+= intel-ipts.o
intel-ipts-objs += companion.o
intel-ipts-objs += ipts.o
intel-ipts-objs += mei.o
intel-ipts-objs += hid.o
intel-ipts-objs += msg-handler.o
intel-ipts-objs += kernel.o
intel-ipts-objs += params.o
intel-ipts-objs += resource.o
intel-ipts-objs += gfx.o
intel-ipts-$(CONFIG_DEBUG_FS) += dbgfs.o

obj-y += companion/
