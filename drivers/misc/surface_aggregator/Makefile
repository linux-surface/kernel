# SPDX-License-Identifier: GPL-2.0-or-later

# For include/trace/define_trace.h to include trace.h
CFLAGS_core.o = -I$(src)

obj-$(CONFIG_SURFACE_AGGREGATOR) += surface_aggregator.o
obj-$(CONFIG_SURFACE_AGGREGATOR) += clients/

surface_aggregator-objs := core.o
surface_aggregator-objs += ssh_parser.o
surface_aggregator-objs += ssh_packet_layer.o
surface_aggregator-objs += ssh_request_layer.o
surface_aggregator-objs += controller.o

ifeq ($(CONFIG_SURFACE_AGGREGATOR_BUS),y)
surface_aggregator-objs += bus.o
endif
