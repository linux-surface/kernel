# SPDX-License-Identifier: GPL-2.0-or-later

# For include/trace/define_trace.h to include ssam_trace.h
CFLAGS_core.o = -I$(src)

obj-$(CONFIG_SURFACE_SAM_SSH) += surface_sam_ssh.o
obj-$(CONFIG_SURFACE_SAM_SSH) += clients/

surface_sam_ssh-objs := core.o
surface_sam_ssh-objs += ssh_parser.o
surface_sam_ssh-objs += ssh_packet_layer.o
surface_sam_ssh-objs += ssh_request_layer.o
surface_sam_ssh-objs += controller.o
surface_sam_ssh-objs += bus.o
