/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Video capture interface for Linux version 2 private header.
 *
 * Copyright (C) 2023 Hans de Goede <hdegoede@redhat.com>
 */

#ifndef _V4L2_DEV_PRIV_H_
#define _V4L2_DEV_PRIV_H_

#if IS_ENABLED(CONFIG_V4L2_ASYNC)
void v4l2_async_debugfs_init(void);
void v4l2_async_debugfs_exit(void);
#else
static inline void v4l2_async_debugfs_init(void) {}
static inline void v4l2_async_debugfs_exit(void) {}
#endif

#endif
