/*
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 *   redistributing this file, you may do so under either license.
 *
 *   GPL LICENSE SUMMARY
 *
 *   Copyright(c) 2015 Intel Corporation. All rights reserved.
 *   Copyright(c) 2017 T-Platforms. All Rights Reserved.
 *   Copyright(c) 2022 YADRO. All Rights Reserved.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2015 Intel Corporation. All rights reserved.
 *   Copyright(c) 2017 T-Platforms. All Rights Reserved.
 *   Copyright(c) 2022 YADRO. All Rights Reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copy
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * PCIe NTB Perf Linux driver
 */

/*
 * How to use this tool, by example.
 *
 * Assuming $DBG_DIR is something like:
 * '/sys/kernel/debug/ntb_perf/0000:00:03.0'
 * Suppose aside from local device there is at least one remote device
 * connected to NTB with index 0.
 *-----------------------------------------------------------------------------
 * Eg: install driver with specified chunk/total orders and dma-enabled flag
 *
 * root@self# insmod ntb_perf.ko chunk_order=19 total_order=28 use_dma
 *-----------------------------------------------------------------------------
 * Eg: check NTB ports (index) and MW mapping information
 *
 * root@self# cat $DBG_DIR/info
 *-----------------------------------------------------------------------------
 * Eg: start performance test with peer (index 0) and get the test metrics
 *
 * root@self# echo 0 > $DBG_DIR/run
 * root@self# cat $DBG_DIR/run
 *-----------------------------------------------------------------------------
 * Eg: start latency test with peer (index 0) poll-waiting and get the metrics
 *
 * Server side:
 * root@self# echo 0 > $DBG_DIR/poll_latency/run_server
 * Client side:
 * root@self# echo 0 > $DBG_DIR/poll_latency/run_client
 * root@self# cat $DBG_DIR/poll_latency/run_client
 *-----------------------------------------------------------------------------
 * Eg: start doorbell latency test with peer (index 0) and get the metrics
 *
 * Server side:
 * root@self# echo 0 > $DBG_DIR/db_latency/run_server
 * Client side:
 * root@self# echo 0 > $DBG_DIR/db_latency/run_client
 * root@self# cat $DBG_DIR/db_latency/run_client
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/dma-mapping.h>
#include <linux/dmaengine.h>
#include <linux/pci.h>
#include <linux/ktime.h>
#include <linux/jiffies.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/sizes.h>
#include <linux/workqueue.h>
#include <linux/debugfs.h>
#include <linux/random.h>
#include <linux/ntb.h>

#define DRIVER_NAME		"ntb_perf"
#define DRIVER_VERSION		"2.3"

MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(DRIVER_VERSION);
MODULE_AUTHOR("Dave Jiang <dave.jiang@intel.com>");
MODULE_DESCRIPTION("PCIe NTB Performance Measurement Tool");

#define MAX_THREADS_CNT		32
#define DEF_THREADS_CNT		1
#define MAX_CHUNK_SIZE		SZ_1M
#define MAX_CHUNK_ORDER		20 /* no larger than 1M */

#define DMA_TRIES		100
#define DMA_MDELAY		10

#define MSG_TRIES		1000
#define MSG_UDELAY_LOW		1000000
#define MSG_UDELAY_HIGH		2000000

#define PERF_BUF_LEN 1024

#define LAT_MIN_TRIES	20
#define RESCHEDULE_RATIO	10000

static unsigned long max_mw_size;
module_param(max_mw_size, ulong, 0644);
MODULE_PARM_DESC(max_mw_size, "Upper limit of memory window size");

static unsigned char chunk_order = 19; /* 512K */
module_param(chunk_order, byte, 0644);
MODULE_PARM_DESC(chunk_order, "Data chunk order [2^n] to transfer");

static unsigned char total_order = 30; /* 1G */
module_param(total_order, byte, 0644);
MODULE_PARM_DESC(total_order, "Total data order [2^n] to transfer");

static bool use_dma; /* default to 0 */
module_param(use_dma, bool, 0644);
MODULE_PARM_DESC(use_dma, "Use DMA engine to measure performance");

static bool perf_latency = true;
module_param(perf_latency, bool, 0644);
MODULE_PARM_DESC(perf_latency, "Measure burst latency");

static unsigned long lat_time_ms = 1000; /* default 1s */
module_param(lat_time_ms, ulong, 0644);
MODULE_PARM_DESC(lat_time_ms, "Time (in ms) to test latency");

static unsigned long lat_timeout_us = 500;
module_param(lat_timeout_us, ulong, 0644);
MODULE_PARM_DESC(lat_timeout_us, "Timeout (in us) to wait for server reply");

static unsigned long peer_timeout_s = 60;
module_param(peer_timeout_s, ulong, 0644);
MODULE_PARM_DESC(peer_timeout_s, "Timeout (in s) to wait for peer link");

/*==============================================================================
 *                         Perf driver data definition
 *==============================================================================
 */

enum perf_cmd {
	PERF_CMD_INVAL = -1,/* invalid spad command */
	PERF_CMD_SSIZE = 0, /* send out buffer size */
	PERF_CMD_RSIZE = 1, /* recv in  buffer size */
	PERF_CMD_SXLAT = 2, /* send in  buffer xlat */
	PERF_CMD_RXLAT = 3, /* recv out buffer xlat */
	PERF_CMD_CLEAR = 4, /* clear allocated memory */
	PERF_STS_DONE  = 5, /* init is done */
	PERF_STS_LNKUP = 6, /* link up state flag */
};

enum run_mode {
	RUN_PL_CLIENT,
	RUN_PL_SERVER,
	RUN_DBL_CLIENT,
	RUN_DBL_SERVER,
};

struct perf_ctx;
struct perf_ext_lat_data;

struct perf_ext_lat_ops {
	int (*init)(struct perf_ext_lat_data *data);
	int (*run)(struct perf_ext_lat_data *data);
	void (*clear)(struct perf_ext_lat_data *data);
};

struct perf_peer {
	struct perf_ctx	*perf;
	int pidx;
	int gidx;

	/* Outbound MW params */
	u64 outbuf_xlat;
	resource_size_t outbuf_size;
	void __iomem *outbuf;
	phys_addr_t out_phys_addr;
	dma_addr_t dma_dst_addr;
	/* Inbound MW params */
	dma_addr_t inbuf_xlat;
	resource_size_t inbuf_size;
	void		*inbuf;

	/* NTB connection setup service */
	struct work_struct	service;
	unsigned long		sts;

	struct completion init_comp;
};
#define to_peer_service(__work) \
	container_of(__work, struct perf_peer, service)

struct perf_thread {
	struct perf_ctx *perf;
	int tidx;

	/* DMA-based test sync parameters */
	atomic_t dma_sync;
	wait_queue_head_t dma_wait;
	struct dma_chan *dma_chan;

	/* Data source and measured statistics */
	void *src;
	u64 copied;
	ktime_t duration;
	ktime_t latency;
	u64 tries;
	int status;
	struct work_struct work;
};
#define to_thread_work(__work) \
	container_of(__work, struct perf_thread, work)

struct perf_ext_lat_data {
	struct perf_ctx *perf;
	ktime_t latency;
	u64 tries;
	int status;
	struct perf_ext_lat_ops ops;
	struct work_struct work;

	union {
		void *src;
		int db;
	};
};
#define to_ext_lat_data(__work) \
	container_of(__work, struct perf_ext_lat_data, work)

struct perf_ctx {
	struct ntb_dev *ntb;

	/* Global device index and peers descriptors */
	int gidx;
	int pcnt;
	struct perf_peer *peers;

	/* Ext latency tests interface */
	enum run_mode mode;
	struct perf_ext_lat_data pldata;
	struct perf_ext_lat_data dbldata;
	atomic_t running;

	/* Performance measuring work-threads interface */
	unsigned long busy_flag;
	wait_queue_head_t twait;
	atomic_t tsync;
	u8 tcnt;
	struct perf_peer *test_peer;
	struct perf_thread threads[MAX_THREADS_CNT];

	/* Scratchpad/Message IO operations */
	int (*cmd_send)(struct perf_peer *peer, enum perf_cmd cmd, u64 data);
	int (*cmd_recv)(struct perf_ctx *perf, int *pidx, enum perf_cmd *cmd,
			u64 *data);

	struct dentry *dbgfs_dir;
};

/*
 * Scratchpads-base commands interface
 */
#define PERF_SPAD_CNT(_pcnt) \
	(3*((_pcnt) + 1))
#define PERF_SPAD_CMD(_gidx) \
	(3*(_gidx))
#define PERF_SPAD_LDATA(_gidx) \
	(3*(_gidx) + 1)
#define PERF_SPAD_HDATA(_gidx) \
	(3*(_gidx) + 2)
#define PERF_SPAD_NOTIFY(_gidx) \
	(BIT_ULL(_gidx))

/*
 * Messages-base commands interface
 */
#define PERF_MSG_CNT		3
#define PERF_MSG_CMD		0
#define PERF_MSG_LDATA		1
#define PERF_MSG_HDATA		2

/*==============================================================================
 *                           Static data declarations
 *==============================================================================
 */

static struct dentry *perf_dbgfs_topdir;

static struct workqueue_struct *perf_wq __read_mostly;

static const u8 stop_word = 0xFF;

/*==============================================================================
 *                  NTB cross-link commands execution service
 *==============================================================================
 */

static void perf_terminate_test(struct perf_ctx *perf);

static inline bool perf_link_is_up(struct perf_peer *peer)
{
	u64 link;

	link = ntb_link_is_up(peer->perf->ntb, NULL, NULL);
	return !!(link & BIT_ULL_MASK(peer->pidx));
}

static int perf_spad_cmd_send(struct perf_peer *peer, enum perf_cmd cmd,
			      u64 data)
{
	struct perf_ctx *perf = peer->perf;
	int try;
	u32 sts;

	dev_dbg(&perf->ntb->dev, "CMD send: %d 0x%llx\n", cmd, data);

	/*
	 * Perform predefined number of attempts before give up.
	 * We are sending the data to the port specific scratchpad, so
	 * to prevent a multi-port access race-condition. Additionally
	 * there is no need in local locking since only thread-safe
	 * service work is using this method.
	 */
	for (try = 0; try < MSG_TRIES; try++) {
		if (!perf_link_is_up(peer))
			return -ENOLINK;

		sts = ntb_peer_spad_read(perf->ntb, peer->pidx,
					 PERF_SPAD_CMD(perf->gidx));
		if (sts != PERF_CMD_INVAL) {
			usleep_range(MSG_UDELAY_LOW, MSG_UDELAY_HIGH);
			continue;
		}

		ntb_peer_spad_write(perf->ntb, peer->pidx,
				    PERF_SPAD_LDATA(perf->gidx),
				    lower_32_bits(data));
		ntb_peer_spad_write(perf->ntb, peer->pidx,
				    PERF_SPAD_HDATA(perf->gidx),
				    upper_32_bits(data));
		ntb_peer_spad_write(perf->ntb, peer->pidx,
				    PERF_SPAD_CMD(perf->gidx),
				    cmd);
		ntb_peer_db_set(perf->ntb, PERF_SPAD_NOTIFY(peer->gidx));

		dev_dbg(&perf->ntb->dev, "DB ring peer %#llx\n",
			PERF_SPAD_NOTIFY(peer->gidx));

		break;
	}

	return try < MSG_TRIES ? 0 : -EAGAIN;
}

static int perf_spad_cmd_recv(struct perf_ctx *perf, int *pidx,
			      enum perf_cmd *cmd, u64 *data)
{
	struct perf_peer *peer;
	u32 val;

	ntb_db_clear(perf->ntb, PERF_SPAD_NOTIFY(perf->gidx));

	/*
	 * We start scanning all over, since cleared DB may have been set
	 * by any peer. Yes, it makes peer with smaller index being
	 * serviced with greater priority, but it's convenient for spad
	 * and message code unification and simplicity.
	 */
	for (*pidx = 0; *pidx < perf->pcnt; (*pidx)++) {
		peer = &perf->peers[*pidx];

		if (!perf_link_is_up(peer))
			continue;

		val = ntb_spad_read(perf->ntb, PERF_SPAD_CMD(peer->gidx));
		if (val == PERF_CMD_INVAL)
			continue;

		*cmd = val;

		val = ntb_spad_read(perf->ntb, PERF_SPAD_LDATA(peer->gidx));
		*data = val;

		val = ntb_spad_read(perf->ntb, PERF_SPAD_HDATA(peer->gidx));
		*data |= (u64)val << 32;

		/* Next command can be retrieved from now */
		ntb_spad_write(perf->ntb, PERF_SPAD_CMD(peer->gidx),
			       PERF_CMD_INVAL);

		dev_dbg(&perf->ntb->dev, "CMD recv: %d 0x%llx\n", *cmd, *data);

		return 0;
	}

	return -ENODATA;
}

static int perf_msg_cmd_send(struct perf_peer *peer, enum perf_cmd cmd,
			     u64 data)
{
	struct perf_ctx *perf = peer->perf;
	int try, ret;
	u64 outbits;

	dev_dbg(&perf->ntb->dev, "CMD send: %d 0x%llx\n", cmd, data);

	/*
	 * Perform predefined number of attempts before give up. Message
	 * registers are free of race-condition problem when accessed
	 * from different ports, so we don't need splitting registers
	 * by global device index. We also won't have local locking,
	 * since the method is used from service work only.
	 */
	outbits = ntb_msg_outbits(perf->ntb);
	for (try = 0; try < MSG_TRIES; try++) {
		if (!perf_link_is_up(peer))
			return -ENOLINK;

		ret = ntb_msg_clear_sts(perf->ntb, outbits);
		if (ret)
			return ret;

		ntb_peer_msg_write(perf->ntb, peer->pidx, PERF_MSG_LDATA,
				   lower_32_bits(data));

		if (ntb_msg_read_sts(perf->ntb) & outbits) {
			usleep_range(MSG_UDELAY_LOW, MSG_UDELAY_HIGH);
			continue;
		}

		ntb_peer_msg_write(perf->ntb, peer->pidx, PERF_MSG_HDATA,
				   upper_32_bits(data));

		/* This call shall trigger peer message event */
		ntb_peer_msg_write(perf->ntb, peer->pidx, PERF_MSG_CMD, cmd);

		break;
	}

	return try < MSG_TRIES ? 0 : -EAGAIN;
}

static int perf_msg_cmd_recv(struct perf_ctx *perf, int *pidx,
			     enum perf_cmd *cmd, u64 *data)
{
	u64 inbits;
	u32 val;

	inbits = ntb_msg_inbits(perf->ntb);

	if (hweight64(ntb_msg_read_sts(perf->ntb) & inbits) < 3)
		return -ENODATA;

	val = ntb_msg_read(perf->ntb, pidx, PERF_MSG_CMD);
	*cmd = val;

	val = ntb_msg_read(perf->ntb, pidx, PERF_MSG_LDATA);
	*data = val;

	val = ntb_msg_read(perf->ntb, pidx, PERF_MSG_HDATA);
	*data |= (u64)val << 32;

	/* Next command can be retrieved from now */
	ntb_msg_clear_sts(perf->ntb, inbits);

	dev_dbg(&perf->ntb->dev, "CMD recv: %d 0x%llx\n", *cmd, *data);

	return 0;
}

static int perf_cmd_send(struct perf_peer *peer, enum perf_cmd cmd, u64 data)
{
	struct perf_ctx *perf = peer->perf;

	if (cmd == PERF_CMD_SSIZE || cmd == PERF_CMD_SXLAT)
		return perf->cmd_send(peer, cmd, data);

	dev_err(&perf->ntb->dev, "Send invalid command\n");
	return -EINVAL;
}

static int perf_cmd_exec(struct perf_peer *peer, enum perf_cmd cmd)
{
	switch (cmd) {
	case PERF_CMD_SSIZE:
	case PERF_CMD_RSIZE:
	case PERF_CMD_SXLAT:
	case PERF_CMD_RXLAT:
	case PERF_CMD_CLEAR:
		break;
	default:
		dev_err(&peer->perf->ntb->dev, "Exec invalid command\n");
		return -EINVAL;
	}

	/* No need of memory barrier, since bit ops have invernal lock */
	set_bit(cmd, &peer->sts);

	dev_dbg(&peer->perf->ntb->dev, "CMD exec: %d\n", cmd);

	(void)queue_work(system_highpri_wq, &peer->service);

	return 0;
}

static int perf_cmd_recv(struct perf_ctx *perf)
{
	struct perf_peer *peer;
	int ret, pidx, cmd;
	u64 data;

	while (!(ret = perf->cmd_recv(perf, &pidx, &cmd, &data))) {
		peer = &perf->peers[pidx];

		switch (cmd) {
		case PERF_CMD_SSIZE:
			peer->inbuf_size = data;
			return perf_cmd_exec(peer, PERF_CMD_RSIZE);
		case PERF_CMD_SXLAT:
			peer->outbuf_xlat = data;
			return perf_cmd_exec(peer, PERF_CMD_RXLAT);
		default:
			dev_err(&perf->ntb->dev, "Recv invalid command\n");
			return -EINVAL;
		}
	}

	/* Return 0 if no data left to process, otherwise an error */
	return ret == -ENODATA ? 0 : ret;
}

static void perf_link_event(void *ctx)
{
	struct perf_ctx *perf = ctx;
	struct perf_peer *peer;
	bool lnk_up;
	int pidx;

	for (pidx = 0; pidx < perf->pcnt; pidx++) {
		peer = &perf->peers[pidx];

		lnk_up = perf_link_is_up(peer);

		if (lnk_up &&
		    !test_and_set_bit(PERF_STS_LNKUP, &peer->sts)) {
			perf_cmd_exec(peer, PERF_CMD_SSIZE);
		} else if (!lnk_up &&
			   test_and_clear_bit(PERF_STS_LNKUP, &peer->sts)) {
			perf_cmd_exec(peer, PERF_CMD_CLEAR);
		}
	}
}

static inline void perf_dbl_pong(struct perf_ctx *perf)
{
	struct perf_ext_lat_data *data = &perf->dbldata;

	ntb_db_clear(perf->ntb, BIT_ULL(data->db));
	data->tries++;
	ntb_peer_db_set(perf->ntb, BIT_ULL(data->db));
}

static void perf_db_event(void *ctx, int vec)
{
	struct perf_ctx *perf = ctx;

	dev_dbg(&perf->ntb->dev, "DB vec %d mask %#llx bits %#llx\n", vec,
		ntb_db_vector_mask(perf->ntb, vec), ntb_db_read(perf->ntb));

	/* Just receive all available commands */
	if (perf->dbldata.db >= 0 &&
				BIT_ULL(perf->dbldata.db) & ntb_db_read(perf->ntb))
		perf_dbl_pong(perf);
	else
		(void)perf_cmd_recv(perf);
}

static void perf_msg_event(void *ctx)
{
	struct perf_ctx *perf = ctx;

	dev_dbg(&perf->ntb->dev, "Msg status bits %#llx\n",
		ntb_msg_read_sts(perf->ntb));

	/* Messages are only sent one-by-one */
	(void)perf_cmd_recv(perf);
}

static const struct ntb_ctx_ops perf_ops = {
	.link_event = perf_link_event,
	.db_event = perf_db_event,
	.msg_event = perf_msg_event
};

static void perf_free_outbuf(struct perf_peer *peer)
{
	(void)ntb_peer_mw_clear_trans(peer->perf->ntb, peer->pidx, peer->gidx);
}

static int perf_setup_outbuf(struct perf_peer *peer)
{
	struct perf_ctx *perf = peer->perf;
	int ret;

	/* Outbuf size can be unaligned due to custom max_mw_size */
	ret = ntb_peer_mw_set_trans(perf->ntb, peer->pidx, peer->gidx,
				    peer->outbuf_xlat, peer->outbuf_size);
	if (ret) {
		dev_err(&perf->ntb->dev, "Failed to set outbuf translation\n");
		return ret;
	}

	/* Initialization is finally done */
	set_bit(PERF_STS_DONE, &peer->sts);
	complete_all(&peer->init_comp);

	return 0;
}

static void perf_free_inbuf(struct perf_peer *peer)
{
	if (!peer->inbuf)
		return;

	(void)ntb_mw_clear_trans(peer->perf->ntb, peer->pidx, peer->gidx);
	dma_free_coherent(&peer->perf->ntb->pdev->dev, peer->inbuf_size,
			  peer->inbuf, peer->inbuf_xlat);
	peer->inbuf = NULL;
}

static int perf_setup_inbuf(struct perf_peer *peer)
{
	resource_size_t xlat_align, size_align, size_max;
	struct perf_ctx *perf = peer->perf;
	int ret;

	/* Get inbound MW parameters */
	ret = ntb_mw_get_align(perf->ntb, peer->pidx, perf->gidx,
			       &xlat_align, &size_align, &size_max);
	if (ret) {
		dev_err(&perf->ntb->dev, "Couldn't get inbuf restrictions\n");
		return ret;
	}

	if (peer->inbuf_size > size_max) {
		dev_err(&perf->ntb->dev, "Too big inbuf size %pa > %pa\n",
			&peer->inbuf_size, &size_max);
		return -EINVAL;
	}

	peer->inbuf_size = round_up(peer->inbuf_size, size_align);

	perf_free_inbuf(peer);

	peer->inbuf = dma_alloc_coherent(&perf->ntb->pdev->dev,
					 peer->inbuf_size, &peer->inbuf_xlat,
					 GFP_KERNEL);
	if (!peer->inbuf) {
		dev_err(&perf->ntb->dev, "Failed to alloc inbuf of %pa\n",
			&peer->inbuf_size);
		return -ENOMEM;
	}
	if (!IS_ALIGNED(peer->inbuf_xlat, xlat_align)) {
		ret = -EINVAL;
		dev_err(&perf->ntb->dev, "Unaligned inbuf allocated\n");
		goto err_free_inbuf;
	}

	ret = ntb_mw_set_trans(perf->ntb, peer->pidx, peer->gidx,
			       peer->inbuf_xlat, peer->inbuf_size);
	if (ret) {
		dev_err(&perf->ntb->dev, "Failed to set inbuf translation\n");
		goto err_free_inbuf;
	}

	/*
	 * We submit inbuf xlat transmission cmd for execution here to follow
	 * the code architecture, even though this method is called from service
	 * work itself so the command will be executed right after it returns.
	 */
	(void)perf_cmd_exec(peer, PERF_CMD_SXLAT);

	return 0;

err_free_inbuf:
	perf_free_inbuf(peer);

	return ret;
}

static void perf_service_work(struct work_struct *work)
{
	struct perf_peer *peer = to_peer_service(work);

	if (test_and_clear_bit(PERF_CMD_SSIZE, &peer->sts))
		perf_cmd_send(peer, PERF_CMD_SSIZE, peer->outbuf_size);

	if (test_and_clear_bit(PERF_CMD_RSIZE, &peer->sts))
		perf_setup_inbuf(peer);

	if (test_and_clear_bit(PERF_CMD_SXLAT, &peer->sts))
		perf_cmd_send(peer, PERF_CMD_SXLAT, peer->inbuf_xlat);

	if (test_and_clear_bit(PERF_CMD_RXLAT, &peer->sts))
		perf_setup_outbuf(peer);

	if (test_and_clear_bit(PERF_CMD_CLEAR, &peer->sts)) {
		init_completion(&peer->init_comp);
		clear_bit(PERF_STS_DONE, &peer->sts);
		if (test_bit(0, &peer->perf->busy_flag) &&
		    peer == peer->perf->test_peer) {
			dev_warn(&peer->perf->ntb->dev,
				"Freeing while test on-fly\n");
			perf_terminate_test(peer->perf);
		}
		perf_free_outbuf(peer);
		perf_free_inbuf(peer);
	}
}

static int perf_init_service(struct perf_ctx *perf)
{
	u64 mask;

	if (ntb_peer_mw_count(perf->ntb) < perf->pcnt) {
		dev_err(&perf->ntb->dev, "Not enough memory windows\n");
		return -EINVAL;
	}

	perf->dbldata.db = -1;

	if (ntb_msg_count(perf->ntb) >= PERF_MSG_CNT) {
		perf->cmd_send = perf_msg_cmd_send;
		perf->cmd_recv = perf_msg_cmd_recv;

		dev_dbg(&perf->ntb->dev, "Message service initialized\n");

		return 0;
	}

	dev_dbg(&perf->ntb->dev, "Message service unsupported\n");

	mask = GENMASK_ULL(perf->pcnt, 0);
	if (ntb_spad_count(perf->ntb) >= PERF_SPAD_CNT(perf->pcnt) &&
	    (ntb_db_valid_mask(perf->ntb) & mask) == mask) {
		perf->cmd_send = perf_spad_cmd_send;
		perf->cmd_recv = perf_spad_cmd_recv;

		dev_dbg(&perf->ntb->dev, "Scratchpad service initialized\n");

		return 0;
	}

	dev_dbg(&perf->ntb->dev, "Scratchpad service unsupported\n");

	dev_err(&perf->ntb->dev, "Command services unsupported\n");

	return -EINVAL;
}

static int perf_enable_service(struct perf_ctx *perf)
{
	u64 mask, incmd_bit;
	int ret, sidx, scnt;

	mask = ntb_db_valid_mask(perf->ntb);
	(void)ntb_db_set_mask(perf->ntb, mask);

	ret = ntb_set_ctx(perf->ntb, perf, &perf_ops);
	if (ret)
		return ret;

	if (perf->cmd_send == perf_msg_cmd_send) {
		u64 inbits, outbits;

		inbits = ntb_msg_inbits(perf->ntb);
		outbits = ntb_msg_outbits(perf->ntb);
		(void)ntb_msg_set_mask(perf->ntb, inbits | outbits);

		incmd_bit = BIT_ULL(__ffs64(inbits));
		ret = ntb_msg_clear_mask(perf->ntb, incmd_bit);

		dev_dbg(&perf->ntb->dev, "MSG sts unmasked %#llx\n", incmd_bit);
	} else {
		scnt = ntb_spad_count(perf->ntb);
		for (sidx = 0; sidx < scnt; sidx++)
			ntb_spad_write(perf->ntb, sidx, PERF_CMD_INVAL);
		incmd_bit = PERF_SPAD_NOTIFY(perf->gidx);
		ret = ntb_db_clear_mask(perf->ntb, incmd_bit);

		dev_dbg(&perf->ntb->dev, "DB bits unmasked %#llx\n", incmd_bit);
	}
	if (ret) {
		ntb_clear_ctx(perf->ntb);
		return ret;
	}

	ntb_link_enable(perf->ntb, NTB_SPEED_AUTO, NTB_WIDTH_AUTO);
	/* Might be not necessary */
	ntb_link_event(perf->ntb);

	return 0;
}

static void perf_disable_service(struct perf_ctx *perf)
{
	int pidx;

	if (perf->cmd_send == perf_msg_cmd_send) {
		u64 inbits;

		inbits = ntb_msg_inbits(perf->ntb);
		(void)ntb_msg_set_mask(perf->ntb, inbits);
	} else {
		(void)ntb_db_set_mask(perf->ntb, PERF_SPAD_NOTIFY(perf->gidx));
	}

	ntb_clear_ctx(perf->ntb);

	for (pidx = 0; pidx < perf->pcnt; pidx++)
		perf_cmd_exec(&perf->peers[pidx], PERF_CMD_CLEAR);

	for (pidx = 0; pidx < perf->pcnt; pidx++)
		flush_work(&perf->peers[pidx].service);

	for (pidx = 0; pidx < perf->pcnt; pidx++) {
		struct perf_peer *peer = &perf->peers[pidx];

		ntb_spad_write(perf->ntb, PERF_SPAD_CMD(peer->gidx), 0);
	}

	ntb_db_clear(perf->ntb, PERF_SPAD_NOTIFY(perf->gidx));

	ntb_link_disable(perf->ntb);
}

/*==============================================================================
 *                      Performance measuring work-thread
 *==============================================================================
 */

static void perf_dma_copy_callback(void *data)
{
	struct perf_thread *pthr = data;

	atomic_dec(&pthr->dma_sync);
	wake_up(&pthr->dma_wait);
}

static int perf_copy_chunk(struct perf_thread *pthr,
			   void __iomem *dst, void *src, size_t len, bool _use_dma)
{
	struct dma_async_tx_descriptor *tx;
	struct dmaengine_unmap_data *unmap;
	struct device *dma_dev;
	int try = 0, ret = 0;
	struct perf_peer *peer = pthr->perf->test_peer;
	void __iomem *vbase;
	void __iomem *dst_vaddr;
	dma_addr_t dst_dma_addr;

	if (!_use_dma) {
		memcpy_toio(dst, src, len);
		goto ret_check_tsync;
	}

	dma_dev = pthr->dma_chan->device->dev;

	if (!is_dma_copy_aligned(pthr->dma_chan->device, offset_in_page(src),
				 offset_in_page(dst), len))
		return -EIO;

	vbase = peer->outbuf;
	dst_vaddr = dst;
	dst_dma_addr = peer->dma_dst_addr + (dst_vaddr - vbase);

	unmap = dmaengine_get_unmap_data(dma_dev, 1, GFP_NOWAIT);
	if (!unmap)
		return -ENOMEM;

	unmap->len = len;
	unmap->addr[0] = dma_map_page(dma_dev, virt_to_page(src),
		offset_in_page(src), len, DMA_TO_DEVICE);
	if (dma_mapping_error(dma_dev, unmap->addr[0])) {
		ret = -EIO;
		goto err_free_resource;
	}
	unmap->to_cnt = 1;

	do {
		tx = dmaengine_prep_dma_memcpy(pthr->dma_chan, dst_dma_addr,
			unmap->addr[0], len, DMA_PREP_INTERRUPT | DMA_CTRL_ACK);
		if (!tx)
			msleep(DMA_MDELAY);
	} while (!tx && (try++ < DMA_TRIES));

	if (!tx) {
		ret = -EIO;
		goto err_free_resource;
	}

	tx->callback = perf_dma_copy_callback;
	tx->callback_param = pthr;
	dma_set_unmap(tx, unmap);

	ret = dma_submit_error(dmaengine_submit(tx));
	if (ret) {
		dmaengine_unmap_put(unmap);
		goto err_free_resource;
	}

	dmaengine_unmap_put(unmap);

	atomic_inc(&pthr->dma_sync);
	dma_async_issue_pending(pthr->dma_chan);

ret_check_tsync:
	return likely(atomic_read(&pthr->perf->tsync) > 0) ? 0 : -EINTR;

err_free_resource:
	dmaengine_unmap_put(unmap);

	return ret;
}

static bool perf_dma_filter(struct dma_chan *chan, void *data)
{
	struct perf_ctx *perf = data;
	int node;

	node = dev_to_node(&perf->ntb->dev);

	return node == NUMA_NO_NODE || node == dev_to_node(chan->device->dev);
}

static int perf_init_test(struct perf_thread *pthr)
{
	struct perf_ctx *perf = pthr->perf;
	dma_cap_mask_t dma_mask;
	struct perf_peer *peer = pthr->perf->test_peer;

	pthr->src = kmalloc_node(perf->test_peer->outbuf_size, GFP_KERNEL,
				 dev_to_node(&perf->ntb->dev));
	if (!pthr->src)
		return -ENOMEM;

	get_random_bytes(pthr->src, perf->test_peer->outbuf_size);

	if (!use_dma)
		return 0;

	dma_cap_zero(dma_mask);
	dma_cap_set(DMA_MEMCPY, dma_mask);
	pthr->dma_chan = dma_request_channel(dma_mask, perf_dma_filter, perf);
	if (!pthr->dma_chan) {
		dev_err(&perf->ntb->dev, "%d: Failed to get DMA channel\n",
			pthr->tidx);
		goto err_free;
	}
	peer->dma_dst_addr =
		dma_map_resource(pthr->dma_chan->device->dev,
				 peer->out_phys_addr, peer->outbuf_size,
				 DMA_FROM_DEVICE, 0);
	if (dma_mapping_error(pthr->dma_chan->device->dev,
			      peer->dma_dst_addr)) {
		dev_err(pthr->dma_chan->device->dev, "%d: Failed to map DMA addr\n",
			pthr->tidx);
		peer->dma_dst_addr = 0;
		dma_release_channel(pthr->dma_chan);
		goto err_free;
	}
	dev_dbg(pthr->dma_chan->device->dev, "%d: Map MMIO %pa to DMA addr %pad\n",
			pthr->tidx,
			&peer->out_phys_addr,
			&peer->dma_dst_addr);

	atomic_set(&pthr->dma_sync, 0);
	return 0;

err_free:
	atomic_dec(&perf->tsync);
	wake_up(&perf->twait);
	kfree(pthr->src);
	return -ENODEV;
}

static int perf_run_test(struct perf_thread *pthr)
{
	struct perf_peer *peer = pthr->perf->test_peer;
	struct perf_ctx *perf = pthr->perf;
	void __iomem *flt_dst, *bnd_dst;
	u64 total_size, chunk_size;
	void *flt_src;
	int ret = 0;

	total_size = 1ULL << total_order;
	chunk_size = 1ULL << chunk_order;
	chunk_size = min_t(u64, peer->outbuf_size, chunk_size);

	flt_src = pthr->src;
	bnd_dst = peer->outbuf + peer->outbuf_size;
	flt_dst = peer->outbuf;

	pthr->duration = ktime_get();

	/* Copied field is cleared on test launch stage */
	while (pthr->copied < total_size) {
		ret = perf_copy_chunk(pthr, flt_dst, flt_src, chunk_size, use_dma);
		if (ret) {
			dev_err(&perf->ntb->dev, "%d: Got error %d on test\n",
				pthr->tidx, ret);
			return ret;
		}

		pthr->copied += chunk_size;

		flt_dst += chunk_size;
		flt_src += chunk_size;
		if (flt_dst >= bnd_dst || flt_dst < peer->outbuf) {
			flt_dst = peer->outbuf;
			flt_src = pthr->src;
		}

		/* Give up CPU to give a chance for other threads to use it */
		schedule();
	}

	return 0;
}

static int perf_sync_test(struct perf_thread *pthr)
{
	struct perf_ctx *perf = pthr->perf;

	if (!use_dma)
		goto no_dma_ret;

	wait_event(pthr->dma_wait,
		   (atomic_read(&pthr->dma_sync) == 0 ||
		    atomic_read(&perf->tsync) < 0));

	if (atomic_read(&perf->tsync) < 0)
		return -EINTR;

no_dma_ret:
	pthr->duration = ktime_sub(ktime_get(), pthr->duration);

	dev_dbg(&perf->ntb->dev, "%d: copied %llu bytes\n",
		pthr->tidx, pthr->copied);

	dev_dbg(&perf->ntb->dev, "%d: lasted %llu usecs\n",
		pthr->tidx, ktime_to_us(pthr->duration));

	dev_dbg(&perf->ntb->dev, "%d: %llu MBytes/s\n", pthr->tidx,
		div64_u64(pthr->copied, ktime_to_us(pthr->duration)));

	return 0;
}

static void perf_clear_test(struct perf_thread *pthr)
{
	struct perf_ctx *perf = pthr->perf;

	if (!use_dma)
		goto no_dma_notify;

	/*
	 * If test finished without errors, termination isn't needed.
	 * We call it anyway just to be sure of the transfers completion.
	 */
	(void)dmaengine_terminate_sync(pthr->dma_chan);
	if (pthr->perf->test_peer->dma_dst_addr)
		dma_unmap_resource(pthr->dma_chan->device->dev,
				   pthr->perf->test_peer->dma_dst_addr,
				   pthr->perf->test_peer->outbuf_size,
				   DMA_FROM_DEVICE, 0);

	dma_release_channel(pthr->dma_chan);

no_dma_notify:
	atomic_dec(&perf->tsync);
	wake_up(&perf->twait);
	kfree(pthr->src);
}

static int perf_run_latency(struct perf_thread *pthr)
{
	struct perf_peer *peer = pthr->perf->test_peer;
	struct ntb_dev *ntb = pthr->perf->ntb;
	void __iomem *flt_dst, *bnd_dst;
	void *flt_src;
	u64 stop_at;
	u32 rem;
	int ret;

	pthr->tries = 0;
	pthr->latency = ktime_get();
	flt_src = pthr->src;
	flt_dst = peer->outbuf;
	bnd_dst = peer->outbuf + peer->outbuf_size;

	stop_at = ktime_get_real_fast_ns() + lat_time_ms * NSEC_PER_MSEC;
	while (ktime_get_real_fast_ns() < stop_at) {
		ret = perf_copy_chunk(pthr, flt_dst, flt_src, 1, false);
		if (ret) {
			dev_err(&ntb->dev, "%d: Latency testing error %d\n",
				pthr->tidx, ret);
			pthr->latency = ktime_set(0, 0);
			return ret;
		}

		pthr->tries++;
		flt_dst++;
		flt_src++;

		if (flt_dst >= bnd_dst || flt_dst < peer->outbuf) {
			flt_dst = peer->outbuf;
			flt_src = pthr->src;
		}

		/* Avoid processor soft lock-ups */
		div_u64_rem(pthr->tries, RESCHEDULE_RATIO, &rem);
		if (!rem)
			schedule();
	}

	/* Stop timer */
	pthr->latency = ktime_sub(ktime_get(), pthr->latency);

	if (pthr->tries < LAT_MIN_TRIES) {
		dev_err(&ntb->dev,
			"%d: Too few steps (%llu) to measure Latency, recommended > %d. Increase value of 'lat_time_ms' parameter\n",
			pthr->tidx, pthr->tries, LAT_MIN_TRIES);
		pthr->latency = ktime_set(0, 0);
		return -EINVAL;
	}

	dev_dbg(&ntb->dev, "%d: made %llu tries, lasted %llu usecs\n",
		pthr->tidx, pthr->tries, ktime_to_us(pthr->latency));

	pthr->latency = ns_to_ktime(ktime_divns(pthr->latency, pthr->tries));

	dev_dbg(&ntb->dev, "%d: latency %llu us (%llu ns)\n", pthr->tidx,
		ktime_to_us(pthr->latency), ktime_to_ns(pthr->latency));

	return 0;
}

static void perf_thread_work(struct work_struct *work)
{
	struct perf_thread *pthr = to_thread_work(work);
	int ret;

	/*
	 * Perform stages in compliance with use_dma flag value.
	 * Test status is changed only if error happened, otherwise
	 * status -ENODATA is kept while test is on-fly. Results
	 * synchronization is performed only if test fininshed
	 * without an error or interruption.
	 */
	ret = perf_init_test(pthr);
	if (ret) {
		pthr->status = ret;
		return;
	}

	ret = perf_run_test(pthr);
	if (ret) {
		pthr->status = ret;
		goto err_clear_test;
	}

	pthr->status = perf_sync_test(pthr);
	if (pthr->status)
		goto err_clear_test;

	if (perf_latency)
		pthr->status = perf_run_latency(pthr);

err_clear_test:
	perf_clear_test(pthr);
}

static int perf_init_pl(struct perf_ext_lat_data *pldata)
{
	struct perf_ctx *perf = pldata->perf;
	struct perf_peer *peer = perf->test_peer;
	u8 *bp;

	pldata->src = kmalloc_node(peer->outbuf_size, GFP_KERNEL,
				dev_to_node(&perf->ntb->dev));
	if (!pldata->src)
		return -ENOMEM;

	/*
	 * Prepare random data to send, guaranteed exclusion of 0x00 (unreceived)
	 * and 0xFF (stop_word)
	 */
	get_random_bytes(pldata->src, peer->outbuf_size);
	for (bp = pldata->src; bp < (u8 *) pldata->src + peer->outbuf_size; bp++)
		while (*bp == 0 || *bp == stop_word)
			*bp = (u8)get_random_int();

	memset(peer->inbuf, 0, peer->inbuf_size);

	return 0;
}

static int perf_poll_peer_reply(volatile u8 *cur)
{
	u64 wait_till = ktime_get_real_fast_ns() + lat_timeout_us * NSEC_PER_USEC;

	while (ktime_get_real_fast_ns() < wait_till) {
		if (*cur == stop_word) {
			*cur = 0;
			return 1;
		}
		if (*cur != 0) {
			*cur = 0;
			return 0;
		}
	}
	return -EINTR;
}

static int perf_run_pl_client(struct perf_ext_lat_data *pldata)
{
	struct perf_ctx *perf = pldata->perf;
	struct perf_peer *peer = perf->test_peer;
	struct ntb_dev *ntb = perf->ntb;
	void *src = pldata->src;
	u64 stop_at;
	int ret;

	dev_dbg(&ntb->dev, "poll_lat: client started.\n");

	pldata->tries = 0;
	pldata->latency = ktime_get();

	stop_at = ktime_get_real_fast_ns() + lat_time_ms * NSEC_PER_MSEC;
	while (ktime_get_real_fast_ns() < stop_at) {
		memcpy_toio(peer->outbuf, src, 1);

		/* Avoid processor soft lock-ups */
		schedule();

		ret = perf_poll_peer_reply(peer->inbuf);
		if (ret < 0) {
			dev_err(&ntb->dev, "Timeout waiting for peer reply on poll latency\n");
			pldata->latency = ktime_set(0, 0);
			return -EINTR;
		} else if (ret == 1) {
			dev_warn(&ntb->dev, "Server terminated on poll latency, stopping\n");
			break;
		} else if (!atomic_read(&perf->running)) {
			dev_err(&ntb->dev, "Poll latency client terminated\n");
			return -EINTR;
		}

		pldata->tries++;
		src++;

		if (src >= pldata->src + peer->outbuf_size)
			src = pldata->src;
	}

	/* Stop timer */
	pldata->latency = ktime_sub(ktime_get(), pldata->latency);
	/* Send stop to peer */
	memcpy_toio(peer->outbuf, &stop_word, 1);

	if (pldata->tries < LAT_MIN_TRIES) {
		dev_err(&ntb->dev,
			"Too few steps (%llu) to measure Latency, recommended > %d. Increase value of 'lat_time_ms' parameter\n",
			pldata->tries, LAT_MIN_TRIES);
		pldata->latency = ktime_set(0, 0);
		return -EINVAL;
	}

	dev_dbg(&ntb->dev, "poll_lat: made %llu tries, lasted %llu usecs\n",
		pldata->tries, ktime_to_us(pldata->latency));

	pldata->latency = ns_to_ktime(ktime_divns(pldata->latency, pldata->tries));

	dev_dbg(&ntb->dev, "poll_lat: latency %llu us (%llu ns)\n",
		ktime_to_us(pldata->latency), ktime_to_ns(pldata->latency));

	return 0;
}

static int perf_run_pl_server(struct perf_ext_lat_data *pldata)
{
	struct perf_ctx *perf = pldata->perf;
	struct perf_peer *peer = perf->test_peer;
	struct ntb_dev *ntb = perf->ntb;
	void *src = pldata->src;
	int ret = 0;

	dev_dbg(&ntb->dev, "poll_lat: server started.\n");

	pldata->tries = 0;

	while (ret != 1 && atomic_read(&perf->running)) {
		ret = perf_poll_peer_reply(peer->inbuf);
		if (!ret) {
			/* Pong to client */
			memcpy_toio(peer->outbuf, src++, 1);
			if (src >= pldata->src + peer->outbuf_size)
				src = pldata->src;

			pldata->tries++;
		}

		/* Avoid processor soft lock-ups */
		schedule();
	}

	if (pldata->tries < LAT_MIN_TRIES)
		dev_warn(&ntb->dev,
			"Poll latency test terminated too early. Increase client's test time\n");

	dev_dbg(&ntb->dev, "poll_lat: server stopped, had responded %llu times\n",
		pldata->tries);

	return atomic_read(&perf->running) ? -ENODATA : -EINTR;
}

static void perf_clear_pl(struct perf_ext_lat_data *pldata)
{
	struct perf_ctx *perf = pldata->perf;
	struct perf_peer *peer = perf->test_peer;

	memset(peer->inbuf, stop_word, 1);
	atomic_set(&perf->running, 0);
	wake_up(&perf->twait);
	kfree(pldata->src);
}

static struct perf_ext_lat_ops perf_pl_client_ops = {
	.init = perf_init_pl,
	.run = perf_run_pl_client,
	.clear = perf_clear_pl
};

static struct perf_ext_lat_ops perf_pl_server_ops = {
	.init = perf_init_pl,
	.run = perf_run_pl_server,
	.clear = perf_clear_pl
};

static int perf_init_dbl(struct perf_ext_lat_data *data)
{
	struct perf_ctx *perf = data->perf;

	data->db = get_bitmask_order(ntb_db_valid_mask(perf->ntb)) - 1;
	dev_dbg(&perf->ntb->dev, "DB bit for latency test: %d\n", data->db);

	if (data->db <= perf->gidx) {
		dev_err(&perf->ntb->dev, "No spare DoorBell found\n");
		data->db = -1;
		return -ENOSPC;
	}

	return ntb_db_clear_mask(perf->ntb, BIT_ULL(data->db));
}

static int perf_run_dbl_client(struct perf_ext_lat_data *data)
{
	struct perf_ctx *perf = data->perf;
	struct ntb_dev *ntb = perf->ntb;
	u64 stop_at;

	dev_dbg(&ntb->dev, "db_lat: client started.\n");

	data->tries = 0;
	data->latency = ktime_get();

	if (ntb_peer_db_set(perf->ntb, BIT_ULL(data->db)))
		return -EIO;

	stop_at = ktime_get_real_fast_ns() + lat_time_ms * NSEC_PER_MSEC;
	while (ktime_get_real_fast_ns() < stop_at) {
		/* Avoid processor soft lock-ups */
		schedule();

		if (!atomic_read(&perf->running)) {
			dev_err(&ntb->dev, "DoorBell latency client terminated\n");
			return -EINTR;
		}
	}

	/* Stop timer */
	data->latency = ktime_sub(ktime_get(), data->latency);

	if (data->tries < LAT_MIN_TRIES) {
		dev_err(&ntb->dev,
			"Too few steps (%llu) to measure Latency, recommended > %d. Increase value of 'lat_time_ms' parameter\n",
			data->tries, LAT_MIN_TRIES);
		data->latency = ktime_set(0, 0);
		return -EINVAL;
	}

	dev_dbg(&ntb->dev, "db_lat: made %llu tries, lasted %llu usecs\n",
		data->tries, ktime_to_us(data->latency));

	data->latency = ns_to_ktime(ktime_divns(data->latency, data->tries));

	dev_dbg(&ntb->dev, "db_lat: latency %llu us (%llu ns)\n",
		ktime_to_us(data->latency), ktime_to_ns(data->latency));

	return 0;
}

static void perf_clear_dbl(struct perf_ext_lat_data *data)
{
	struct perf_ctx *perf = data->perf;

	data->db = -1;
	ntb_db_set_mask(perf->ntb, BIT_ULL(data->db));
	atomic_set(&perf->running, 0);
	wake_up(&perf->twait);
}

static struct perf_ext_lat_ops perf_dbl_client_ops = {
	.init = perf_init_dbl,
	.run = perf_run_dbl_client,
	.clear = perf_clear_dbl
};

static void perf_ext_lat_work(struct work_struct *work)
{
	struct perf_ext_lat_data *data = to_ext_lat_data(work);

	if (!data->ops.init || !data->ops.run || !data->ops.clear) {
		struct perf_ctx *perf = data->perf;

		data->status = -EFAULT;
		atomic_set(&perf->running, 0);
		wake_up(&perf->twait);
		return;
	}

	data->status = data->ops.init(data);
	if (data->status)
		return;

	data->status = data->ops.run(data);

	data->ops.clear(data);
}

static int perf_set_tcnt(struct perf_ctx *perf, u8 tcnt)
{
	if (tcnt == 0 || tcnt > MAX_THREADS_CNT)
		return -EINVAL;

	if (test_and_set_bit_lock(0, &perf->busy_flag))
		return -EBUSY;

	perf->tcnt = tcnt;

	clear_bit_unlock(0, &perf->busy_flag);

	return 0;
}

static void perf_terminate_test(struct perf_ctx *perf)
{
	int tidx;

	atomic_set(&perf->tsync, -1);
	atomic_set(&perf->running, 0);
	wake_up(&perf->twait);
	cancel_work_sync(&perf->pldata.work);
	cancel_work_sync(&perf->dbldata.work);

	for (tidx = 0; tidx < MAX_THREADS_CNT; tidx++) {
		wake_up(&perf->threads[tidx].dma_wait);
		cancel_work_sync(&perf->threads[tidx].work);
	}
}

static int perf_submit_test(struct perf_peer *peer)
{
	struct perf_ctx *perf = peer->perf;
	struct perf_thread *pthr;
	int tidx, ret;

	ret = wait_for_completion_interruptible_timeout(&peer->init_comp,
			msecs_to_jiffies(peer_timeout_s * 1000));
	if (ret <= 0)
		return ret ? ret : -ETIMEDOUT;

	if (test_and_set_bit_lock(0, &perf->busy_flag))
		return -EBUSY;

	perf->test_peer = peer;
	atomic_set(&perf->tsync, perf->tcnt);

	for (tidx = 0; tidx < MAX_THREADS_CNT; tidx++) {
		pthr = &perf->threads[tidx];

		pthr->status = -ENODATA;
		pthr->copied = 0;
		pthr->duration = ktime_set(0, 0);
		if (tidx < perf->tcnt)
			(void)queue_work(perf_wq, &pthr->work);
	}

	ret = wait_event_interruptible(perf->twait,
				       atomic_read(&perf->tsync) <= 0);
	if (ret == -ERESTARTSYS) {
		perf_terminate_test(perf);
		ret = -EINTR;
	}

	clear_bit_unlock(0, &perf->busy_flag);

	return ret;
}

static int perf_submit_ext_lat(struct perf_peer *peer)
{
	struct perf_ctx *perf = peer->perf;
	int ret;

	ret = wait_for_completion_interruptible_timeout(&peer->init_comp,
			msecs_to_jiffies(peer_timeout_s * 1000));
	if (ret <= 0)
		return ret ? ret : -ETIMEDOUT;

	if (test_and_set_bit_lock(0, &perf->busy_flag))
		return -EBUSY;

	perf->test_peer = peer;
	atomic_set(&perf->running, 1);
	perf->pldata.status = -ENODATA;
	perf->pldata.tries = 0;
	perf->pldata.latency = ktime_set(0, 0);
	perf->dbldata.status = -ENODATA;
	perf->dbldata.tries = 0;
	perf->dbldata.latency = ktime_set(0, 0);

	switch (perf->mode) {
	case RUN_PL_SERVER:
		perf->pldata.ops = perf_pl_server_ops;
		(void)queue_work(perf_wq, &perf->pldata.work);
		break;
	case RUN_PL_CLIENT:
		perf->pldata.ops = perf_pl_client_ops;
		(void)queue_work(perf_wq, &perf->pldata.work);
		break;
	case RUN_DBL_SERVER:
		ret = perf_init_dbl(&perf->dbldata);
		dev_dbg(&perf->ntb->dev, "db_lat: server started.\n");
		goto submit_exit;
	case RUN_DBL_CLIENT:
		perf->dbldata.ops = perf_dbl_client_ops;
		(void)queue_work(perf_wq, &perf->dbldata.work);
		break;
	default:
		ret = -EINVAL;
		goto submit_exit;
	}

	ret = wait_event_interruptible(perf->twait,
				       !atomic_read(&perf->running));
	if (ret == -ERESTARTSYS) {
		perf_terminate_test(perf);
		ret = -EINTR;
	}

submit_exit:
	clear_bit_unlock(0, &perf->busy_flag);

	return ret;
}

static int perf_read_stats(struct perf_ctx *perf, char *buf,
			   size_t size, ssize_t *pos)
{
	struct perf_thread *pthr;
	int tidx;

	if (test_and_set_bit_lock(0, &perf->busy_flag))
		return -EBUSY;

	(*pos) += scnprintf(buf + *pos, size - *pos,
		"    Peer %d test statistics:\n", perf->test_peer->pidx);

	for (tidx = 0; tidx < MAX_THREADS_CNT; tidx++) {
		pthr = &perf->threads[tidx];

		if (pthr->status == -ENODATA)
			continue;

		if (pthr->status) {
			(*pos) += scnprintf(buf + *pos, size - *pos,
				"%d: error status %d\n", tidx, pthr->status);
			continue;
		}

		(*pos) += scnprintf(buf + *pos, size - *pos,
			"%d: copied %llu bytes in %llu usecs, %llu MBytes/s\n",
			tidx, pthr->copied, ktime_to_us(pthr->duration),
			div64_u64(pthr->copied, ktime_to_us(pthr->duration)));

		if (perf_latency && ktime_compare(pthr->latency, ktime_set(0, 0))) {
			if (ktime_to_us(pthr->latency) < 10) {
				(*pos) += scnprintf(buf + *pos, size - *pos,
						"%d: latency %llu ns\n",
						tidx, ktime_to_ns(pthr->latency));
			} else {
				(*pos) += scnprintf(buf + *pos, size - *pos,
						"%d: latency %llu us\n",
						tidx, ktime_to_us(pthr->latency));
			}
		}
	}

	clear_bit_unlock(0, &perf->busy_flag);

	return 0;
}

static void perf_init_workers(struct perf_ctx *perf)
{
	struct perf_thread *pthr;
	int tidx;

	perf->tcnt = DEF_THREADS_CNT;
	perf->test_peer = &perf->peers[0];
	init_waitqueue_head(&perf->twait);

	perf->pldata.perf = perf;
	INIT_WORK(&perf->pldata.work, perf_ext_lat_work);
	perf->pldata.status = -ENODATA;

	perf->dbldata.perf = perf;
	INIT_WORK(&perf->dbldata.work, perf_ext_lat_work);
	perf->dbldata.status = -ENODATA;

	for (tidx = 0; tidx < MAX_THREADS_CNT; tidx++) {
		pthr = &perf->threads[tidx];

		pthr->perf = perf;
		pthr->tidx = tidx;
		pthr->status = -ENODATA;
		init_waitqueue_head(&pthr->dma_wait);
		INIT_WORK(&pthr->work, perf_thread_work);
	}
}

static void perf_clear_workers(struct perf_ctx *perf)
{
	perf_terminate_test(perf);
}

/*==============================================================================
 *                               DebugFS nodes
 *==============================================================================
 */

static ssize_t perf_dbgfs_read_info(struct file *filep, char __user *ubuf,
				    size_t size, loff_t *offp)
{
	struct perf_ctx *perf = filep->private_data;
	struct perf_peer *peer;
	size_t buf_size;
	ssize_t pos = 0;
	int ret, pidx;
	char *buf;

	buf_size = min_t(size_t, size, 0x1000U);

	buf = kmalloc(buf_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	pos += scnprintf(buf + pos, buf_size - pos,
		"    Performance measuring tool info:\n\n");

	pos += scnprintf(buf + pos, buf_size - pos,
		"Local port %d, Global index %d\n", ntb_port_number(perf->ntb),
		perf->gidx);
	pos += scnprintf(buf + pos, buf_size - pos, "Test status: ");
	if (test_bit(0, &perf->busy_flag)) {
		pos += scnprintf(buf + pos, buf_size - pos,
			"on-fly with port %d (%d)\n",
			ntb_peer_port_number(perf->ntb, perf->test_peer->pidx),
			perf->test_peer->pidx);
	} else {
		pos += scnprintf(buf + pos, buf_size - pos, "idle\n");
	}

	for (pidx = 0; pidx < perf->pcnt; pidx++) {
		peer = &perf->peers[pidx];

		pos += scnprintf(buf + pos, buf_size - pos,
			"Port %d (%d), Global index %d:\n",
			ntb_peer_port_number(perf->ntb, peer->pidx), peer->pidx,
			peer->gidx);

		pos += scnprintf(buf + pos, buf_size - pos,
			"\tLink status: %s\n",
			test_bit(PERF_STS_LNKUP, &peer->sts) ? "up" : "down");

		pos += scnprintf(buf + pos, buf_size - pos,
			"\tOut buffer addr 0x%pK\n", peer->outbuf);

		pos += scnprintf(buf + pos, buf_size - pos,
			"\tOut buff phys addr %pa[p]\n", &peer->out_phys_addr);

		pos += scnprintf(buf + pos, buf_size - pos,
			"\tOut buffer size %pa\n", &peer->outbuf_size);

		pos += scnprintf(buf + pos, buf_size - pos,
			"\tOut buffer xlat 0x%016llx[p]\n", peer->outbuf_xlat);

		if (!peer->inbuf) {
			pos += scnprintf(buf + pos, buf_size - pos,
				"\tIn buffer addr: unallocated\n");
			continue;
		}

		pos += scnprintf(buf + pos, buf_size - pos,
			"\tIn buffer addr 0x%pK\n", peer->inbuf);

		pos += scnprintf(buf + pos, buf_size - pos,
			"\tIn buffer size %pa\n", &peer->inbuf_size);

		pos += scnprintf(buf + pos, buf_size - pos,
			"\tIn buffer xlat %pad[p]\n", &peer->inbuf_xlat);
	}

	ret = simple_read_from_buffer(ubuf, size, offp, buf, pos);
	kfree(buf);

	return ret;
}

static const struct file_operations perf_dbgfs_info = {
	.open = simple_open,
	.read = perf_dbgfs_read_info
};

static ssize_t perf_dbgfs_read_run(struct file *filep, char __user *ubuf,
				   size_t size, loff_t *offp)
{
	struct perf_ctx *perf = filep->private_data;
	ssize_t ret, pos = 0;
	char *buf;

	buf = kmalloc(PERF_BUF_LEN, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	ret = perf_read_stats(perf, buf, PERF_BUF_LEN, &pos);
	if (ret)
		goto err_free;

	ret = simple_read_from_buffer(ubuf, size, offp, buf, pos);
err_free:
	kfree(buf);

	return ret;
}

static ssize_t perf_dbgfs_write_run(struct file *filep, const char __user *ubuf,
				    size_t size, loff_t *offp)
{
	struct perf_ctx *perf = filep->private_data;
	struct perf_peer *peer;
	int pidx, ret;

	ret = kstrtoint_from_user(ubuf, size, 0, &pidx);
	if (ret)
		return ret;

	if (pidx < 0 || pidx >= perf->pcnt)
		return -EINVAL;

	peer = &perf->peers[pidx];

	ret = perf_submit_test(peer);
	if (ret)
		return ret;

	return size;
}

static const struct file_operations perf_dbgfs_run = {
	.open = simple_open,
	.read = perf_dbgfs_read_run,
	.write = perf_dbgfs_write_run
};

static ssize_t perf_dbgfs_read_run_pl(struct file *filep, char __user *ubuf,
				   size_t fsize, loff_t *offp)
{
	struct perf_ctx *perf = filep->private_data;
	ssize_t size = PERF_BUF_LEN;
	ssize_t pos = 0;
	ssize_t ret;
	char *buf;

	if (test_and_set_bit_lock(0, &perf->busy_flag))
		return -EBUSY;

	buf = kmalloc(size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	pos += scnprintf(buf + pos, size - pos,
		"    Peer %d test statistics:\n", perf->test_peer->pidx);

	if (perf->pldata.status != -ENODATA) {
		if (perf->pldata.status) {
			pos += scnprintf(buf + pos, size - pos,
				"poll latency: error status %d\n", perf->pldata.status);
		} else {
			if (ktime_to_us(perf->pldata.latency) < 10) {
				pos += scnprintf(buf + pos, size - pos,
						"poll latency %llu ns\n",
						ktime_to_ns(perf->pldata.latency));
			} else {
				pos += scnprintf(buf + pos, size - pos,
						"poll latency %llu us\n",
						ktime_to_us(perf->pldata.latency));
			}
		}
	} else {
		pos += scnprintf(buf + pos, size - pos, "Test did not run\n");
	}

	ret = simple_read_from_buffer(ubuf, fsize, offp, buf, pos);

	kfree(buf);

	clear_bit_unlock(0, &perf->busy_flag);

	return ret;
}

static ssize_t perf_dbgfs_write_run_ext(struct file *filep, const char __user *ubuf,
					size_t size, loff_t *offp, enum run_mode mode)
{
	struct perf_ctx *perf = filep->private_data;
	struct ntb_dev *ntb = perf->ntb;
	struct perf_peer *peer;
	int pidx, ret;

	ret = kstrtoint_from_user(ubuf, size, 0, &pidx);
	if (ret)
		return ret;

	if (pidx < 0) {
		switch (mode) {
		case RUN_PL_SERVER:
			dev_dbg(&ntb->dev, "poll_lat: kill server\n");
			if (test_bit(0, &perf->busy_flag)) {
				peer = perf->test_peer;
				/* Send stop to client */
				memcpy_toio(peer->outbuf, &stop_word, 1);
			}
			perf_terminate_test(perf);
			clear_bit_unlock(0, &perf->busy_flag);
			return size;
		case RUN_DBL_SERVER:
			dev_dbg(&ntb->dev, "db_lat: kill server\n");
			perf_clear_dbl(&perf->dbldata);
			clear_bit_unlock(0, &perf->busy_flag);
			return size;
		default:
			return -EINVAL;
		}
	}

	if (pidx >= perf->pcnt)
		return -EINVAL;

	peer = &perf->peers[pidx];
	perf->mode = mode;

	ret = perf_submit_ext_lat(peer);

	return ret ? ret : size;
}

static ssize_t perf_dbgfs_write_run_pl_client(struct file *filep,
					const char __user *ubuf, size_t size, loff_t *offp)
{
	return perf_dbgfs_write_run_ext(filep, ubuf, size, offp, RUN_PL_CLIENT);
}

static const struct file_operations perf_dbgfs_run_pl_client = {
	.open = simple_open,
	.read = perf_dbgfs_read_run_pl,
	.write = perf_dbgfs_write_run_pl_client
};

static ssize_t perf_dbgfs_write_run_pl_server(struct file *filep,
					const char __user *ubuf, size_t size, loff_t *offp)
{
	return perf_dbgfs_write_run_ext(filep, ubuf, size, offp, RUN_PL_SERVER);
}

static const struct file_operations perf_dbgfs_run_pl_server = {
	.open = simple_open,
	.read = perf_dbgfs_read_run_pl,
	.write = perf_dbgfs_write_run_pl_server
};

static ssize_t perf_dbgfs_read_run_dbl(struct file *filep, char __user *ubuf,
				   size_t fsize, loff_t *offp)
{
	struct perf_ctx *perf = filep->private_data;
	ssize_t size = PERF_BUF_LEN;
	ssize_t pos = 0;
	ssize_t ret;
	char *buf;

	if (test_and_set_bit_lock(0, &perf->busy_flag))
		return -EBUSY;

	buf = kmalloc(size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	pos += scnprintf(buf + pos, size - pos,
		"    Peer %d test statistics:\n", perf->test_peer->pidx);

	if (perf->dbldata.status != -ENODATA) {
		if (perf->dbldata.status) {
			pos += scnprintf(buf + pos, size - pos,
				"doorbell latency: error status %d\n", perf->dbldata.status);
		} else {
			if (ktime_to_us(perf->dbldata.latency) < 10) {
				pos += scnprintf(buf + pos, size - pos,
						"doorbell latency %llu ns\n",
						ktime_to_ns(perf->dbldata.latency));
			} else {
				pos += scnprintf(buf + pos, size - pos,
						"doorbell latency %llu us\n",
						ktime_to_us(perf->dbldata.latency));
			}
		}
	} else {
		pos += scnprintf(buf + pos, size - pos, "Test did not run\n");
	}

	ret = simple_read_from_buffer(ubuf, fsize, offp, buf, pos);

	kfree(buf);

	clear_bit_unlock(0, &perf->busy_flag);

	return ret;
}

static ssize_t perf_dbgfs_write_run_dbl_client(struct file *filep,
					const char __user *ubuf, size_t size, loff_t *offp)
{
	return perf_dbgfs_write_run_ext(filep, ubuf, size, offp, RUN_DBL_CLIENT);
}

static const struct file_operations perf_dbgfs_run_dbl_client = {
	.open = simple_open,
	.read = perf_dbgfs_read_run_dbl,
	.write = perf_dbgfs_write_run_dbl_client
};

static ssize_t perf_dbgfs_write_run_dbl_server(struct file *filep,
					const char __user *ubuf, size_t size, loff_t *offp)
{
	return perf_dbgfs_write_run_ext(filep, ubuf, size, offp, RUN_DBL_SERVER);
}

static const struct file_operations perf_dbgfs_run_dbl_server = {
	.open = simple_open,
	.read = perf_dbgfs_read_run_dbl,
	.write = perf_dbgfs_write_run_dbl_server
};

static ssize_t perf_dbgfs_read_tcnt(struct file *filep, char __user *ubuf,
				    size_t size, loff_t *offp)
{
	struct perf_ctx *perf = filep->private_data;
	char buf[8];
	ssize_t pos;

	pos = scnprintf(buf, sizeof(buf), "%hhu\n", perf->tcnt);

	return simple_read_from_buffer(ubuf, size, offp, buf, pos);
}

static ssize_t perf_dbgfs_write_tcnt(struct file *filep,
				     const char __user *ubuf,
				     size_t size, loff_t *offp)
{
	struct perf_ctx *perf = filep->private_data;
	int ret;
	u8 val;

	ret = kstrtou8_from_user(ubuf, size, 0, &val);
	if (ret)
		return ret;

	ret = perf_set_tcnt(perf, val);
	if (ret)
		return ret;

	return size;
}

static ssize_t perf_dbgfs_read_lattrs(struct file *filep, char __user *ubuf,
				    size_t size, loff_t *offp)
{
	size_t buf_size = min_t(size_t, size, PERF_BUF_LEN);
	struct perf_ctx *perf = filep->private_data;
	ssize_t pos, ret;
	char *buf;
	int tidx;

	buf = kmalloc(buf_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	pos = scnprintf(buf, buf_size, "    Peer %d latency try count:\n",
			perf->test_peer->pidx);

	for (tidx = 0; tidx < perf->tcnt; tidx++) {
		struct perf_thread *pthr = &perf->threads[tidx];

		pos += scnprintf(buf + pos, buf_size - pos,
				"%d: made %llu tries\n", tidx, pthr->tries);
	}

	ret = simple_read_from_buffer(ubuf, size, offp, buf, pos);

	kfree(buf);

	return ret;
}

static ssize_t perf_dbgfs_read_inbuf(struct file *filep, char __user *ubuf,
					size_t size, loff_t *offp)
{
	struct perf_ctx *perf = filep->private_data;
	char buf[32];
	ssize_t pos;
	u64 *value;

	if (!perf->test_peer || !perf->test_peer->inbuf) {
		pos = scnprintf(buf, sizeof(buf), "NULL\n");
	} else {
		value = perf->test_peer->inbuf;
		pos = scnprintf(buf, sizeof(buf), "0x%llx\n", *value);
	}

	return simple_read_from_buffer(ubuf, size, offp, buf, pos);
}

static const struct file_operations perf_dbgfs_tcnt = {
	.open = simple_open,
	.read = perf_dbgfs_read_tcnt,
	.write = perf_dbgfs_write_tcnt
};

static const struct file_operations perf_dbgfs_lattrs = {
	.open = simple_open,
	.read = perf_dbgfs_read_lattrs
};

static const struct file_operations perf_dbgfs_inbuf = {
	.open = simple_open,
	.read = perf_dbgfs_read_inbuf,
};

static void perf_setup_dbgfs(struct perf_ctx *perf)
{
	struct pci_dev *pdev = perf->ntb->pdev;
	struct dentry *burst_lat_dir;
	struct dentry *poll_lat_dir;
	struct dentry *db_lat_dir;

	perf->dbgfs_dir = debugfs_create_dir(pci_name(pdev), perf_dbgfs_topdir);
	if (!perf->dbgfs_dir) {
		dev_warn(&perf->ntb->dev, "DebugFS unsupported\n");
		return;
	}

	debugfs_create_file("info", 0600, perf->dbgfs_dir, perf,
			    &perf_dbgfs_info);

	debugfs_create_symlink("run", perf->dbgfs_dir, "burst_latency/run");

	debugfs_create_symlink("threads_count", perf->dbgfs_dir,
				"burst_latency/threads_count");

	/* They are made read-only for test exec safety and integrity */
	debugfs_create_u8("chunk_order", 0500, perf->dbgfs_dir, &chunk_order);

	debugfs_create_u8("total_order", 0500, perf->dbgfs_dir, &total_order);

	debugfs_create_bool("use_dma", 0500, perf->dbgfs_dir, &use_dma);

	debugfs_create_file("inbuf", 0400, perf->dbgfs_dir, perf,
			    &perf_dbgfs_inbuf);

	/* burst_latency subdir */

	burst_lat_dir = debugfs_create_dir("burst_latency", perf->dbgfs_dir);

	debugfs_create_file("run", 0600, burst_lat_dir, perf, &perf_dbgfs_run);

	debugfs_create_file("threads_count", 0600, burst_lat_dir, perf,
			    &perf_dbgfs_tcnt);

	debugfs_create_file("tries", 0400, burst_lat_dir, perf,
			    &perf_dbgfs_lattrs);

	/* poll_latency subdir */

	poll_lat_dir = debugfs_create_dir("poll_latency", perf->dbgfs_dir);

	debugfs_create_file("run_client", 0600, poll_lat_dir, perf,
			    &perf_dbgfs_run_pl_client);

	debugfs_create_file("run_server", 0600, poll_lat_dir, perf,
			    &perf_dbgfs_run_pl_server);

	debugfs_create_u64("tries", 0400, poll_lat_dir, &perf->pldata.tries);

	/* db_latency subdir */

	db_lat_dir = debugfs_create_dir("db_latency", perf->dbgfs_dir);

	debugfs_create_file("run_client", 0600, db_lat_dir, perf,
			    &perf_dbgfs_run_dbl_client);

	debugfs_create_file("run_server", 0600, db_lat_dir, perf,
			    &perf_dbgfs_run_dbl_server);

	debugfs_create_u64("tries", 0400, db_lat_dir, &perf->dbldata.tries);
}

static void perf_clear_dbgfs(struct perf_ctx *perf)
{
	debugfs_remove_recursive(perf->dbgfs_dir);
}

/*==============================================================================
 *                        Basic driver initialization
 *==============================================================================
 */

static struct perf_ctx *perf_create_data(struct ntb_dev *ntb)
{
	struct perf_ctx *perf;

	perf = devm_kzalloc(&ntb->dev, sizeof(*perf), GFP_KERNEL);
	if (!perf)
		return ERR_PTR(-ENOMEM);

	perf->pcnt = ntb_peer_port_count(ntb);
	perf->peers = devm_kcalloc(&ntb->dev, perf->pcnt, sizeof(*perf->peers),
				  GFP_KERNEL);
	if (!perf->peers)
		return ERR_PTR(-ENOMEM);

	perf->ntb = ntb;

	return perf;
}

static int perf_setup_peer_mw(struct perf_peer *peer)
{
	struct perf_ctx *perf = peer->perf;
	phys_addr_t phys_addr;
	int ret;

	/* Get outbound MW parameters and map it */
	ret = ntb_peer_mw_get_addr(perf->ntb, perf->gidx, &phys_addr,
				   &peer->outbuf_size);
	if (ret)
		return ret;

	peer->outbuf = devm_ioremap_wc(&perf->ntb->dev, phys_addr,
					peer->outbuf_size);
	if (!peer->outbuf)
		return -ENOMEM;

	peer->out_phys_addr = phys_addr;

	if (max_mw_size && peer->outbuf_size > max_mw_size) {
		peer->outbuf_size = max_mw_size;
		dev_warn(&peer->perf->ntb->dev,
			"Peer %d outbuf reduced to %pa\n", peer->pidx,
			&peer->outbuf_size);
	}

	return 0;
}

static int perf_init_peers(struct perf_ctx *perf)
{
	struct perf_peer *peer;
	int pidx, lport, ret;

	lport = ntb_port_number(perf->ntb);
	perf->gidx = -1;
	for (pidx = 0; pidx < perf->pcnt; pidx++) {
		peer = &perf->peers[pidx];

		peer->perf = perf;
		peer->pidx = pidx;
		if (lport < ntb_peer_port_number(perf->ntb, pidx)) {
			if (perf->gidx == -1)
				perf->gidx = pidx;
			peer->gidx = pidx + 1;
		} else {
			peer->gidx = pidx;
		}
		INIT_WORK(&peer->service, perf_service_work);
		init_completion(&peer->init_comp);
	}
	if (perf->gidx == -1)
		perf->gidx = pidx;

	/*
	 * Hardware with only two ports may not have unique port
	 * numbers. In this case, the gidxs should all be zero.
	 */
	if (perf->pcnt == 1 &&  ntb_port_number(perf->ntb) == 0 &&
	    ntb_peer_port_number(perf->ntb, 0) == 0) {
		perf->gidx = 0;
		perf->peers[0].gidx = 0;
	}

	for (pidx = 0; pidx < perf->pcnt; pidx++) {
		ret = perf_setup_peer_mw(&perf->peers[pidx]);
		if (ret)
			return ret;
	}

	dev_dbg(&perf->ntb->dev, "Global port index %d\n", perf->gidx);

	return 0;
}

static int perf_probe(struct ntb_client *client, struct ntb_dev *ntb)
{
	struct perf_ctx *perf;
	int ret;

	perf = perf_create_data(ntb);
	if (IS_ERR(perf))
		return PTR_ERR(perf);

	ret = perf_init_peers(perf);
	if (ret)
		return ret;

	perf_init_workers(perf);

	ret = perf_init_service(perf);
	if (ret)
		return ret;

	ret = perf_enable_service(perf);
	if (ret)
		return ret;

	perf_setup_dbgfs(perf);

	return 0;
}

static void perf_remove(struct ntb_client *client, struct ntb_dev *ntb)
{
	struct perf_ctx *perf = ntb->ctx;

	perf_clear_dbgfs(perf);

	perf_disable_service(perf);

	perf_clear_workers(perf);
}

static struct ntb_client perf_client = {
	.ops = {
		.probe = perf_probe,
		.remove = perf_remove
	}
};

static int __init perf_init(void)
{
	int ret;

	if (chunk_order > MAX_CHUNK_ORDER) {
		chunk_order = MAX_CHUNK_ORDER;
		pr_info("Chunk order reduced to %hhu\n", chunk_order);
	}

	if (total_order < chunk_order) {
		total_order = chunk_order;
		pr_info("Total data order reduced to %hhu\n", total_order);
	}

	perf_wq = alloc_workqueue("perf_wq", WQ_UNBOUND | WQ_SYSFS, 0);
	if (!perf_wq)
		return -ENOMEM;

	if (debugfs_initialized())
		perf_dbgfs_topdir = debugfs_create_dir(KBUILD_MODNAME, NULL);

	ret = ntb_register_client(&perf_client);
	if (ret) {
		debugfs_remove_recursive(perf_dbgfs_topdir);
		destroy_workqueue(perf_wq);
	}

	return ret;
}
module_init(perf_init);

static void __exit perf_exit(void)
{
	ntb_unregister_client(&perf_client);
	debugfs_remove_recursive(perf_dbgfs_topdir);
	destroy_workqueue(perf_wq);
}
module_exit(perf_exit);
