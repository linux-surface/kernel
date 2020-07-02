// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Surface Serial Hub (SSH) driver for communication with the Surface/System
 * Aggregator Module.
 */

#include <asm/unaligned.h>
#include <linux/acpi.h>
#include <linux/atomic.h>
#include <linux/completion.h>
#include <linux/crc-ccitt.h>
#include <linux/dmaengine.h>
#include <linux/gpio/consumer.h>
#include <linux/interrupt.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/kfifo.h>
#include <linux/kref.h>
#include <linux/kthread.h>
#include <linux/ktime.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/pm.h>
#include <linux/refcount.h>
#include <linux/serdev.h>
#include <linux/spinlock.h>
#include <linux/sysfs.h>
#include <linux/workqueue.h>

#include "surface_sam_ssh.h"

#define CREATE_TRACE_POINTS
#include "surface_sam_ssh_trace.h"


/* -- TODO. ----------------------------------------------------------------- */

#define SSH_RQST_TAG_FULL			"surface_sam_ssh_rqst: "
#define SSH_RQST_TAG				"rqst: "

#define SSH_SUPPORTED_FLOW_CONTROL_MASK		(~((u8) ACPI_UART_FLOW_CONTROL_HW))


/* -- Error injection helpers. ---------------------------------------------- */

#ifdef CONFIG_SURFACE_SAM_SSH_ERROR_INJECTION
#define noinline_if_inject noinline
#else /* CONFIG_SURFACE_SAM_SSH_ERROR_INJECTION */
#define noinline_if_inject inline
#endif /* CONFIG_SURFACE_SAM_SSH_ERROR_INJECTION */


/* -- Public interface. ----------------------------------------------------- */

enum ssam_request_flags {
	SSAM_REQUEST_HAS_RESPONSE = BIT(0),
	SSAM_REQUEST_UNSEQUENCED  = BIT(1),
};

struct ssam_request {
	u8 target_category;
	u8 command_id;
	u8 instance_id;
	u8 channel;
	u16 flags;
	u16 length;
	u8 *payload;
};


/* -- Common/utility functions. --------------------------------------------- */

static inline u16 ssh_crc(const u8 *buf, size_t len)
{
	return crc_ccitt_false(0xffff, buf, len);
}

static inline u16 __ssh_rqid_next(u16 rqid)
{
	return rqid > 0 ? rqid + 1u : rqid + SURFACE_SAM_SSH_NUM_EVENTS + 1u;
}

static inline u16 ssh_event_to_rqid(u16 event)
{
	return event + 1u;
}

static inline u16 ssh_rqid_to_event(u16 rqid)
{
	return rqid - 1u;
}

static inline bool ssh_rqid_is_event(u16 rqid)
{
	return ssh_rqid_to_event(rqid) < SURFACE_SAM_SSH_NUM_EVENTS;
}

static inline int ssh_tc_to_rqid(u8 tc)
{
#if 0	// TODO: check if it works without this
	/*
	 * TC=0x08 represents the input subsystem on Surface Laptop 1 and 2.
	 * This is mapped on Windows to RQID=0x0001. As input events seem to be
	 * somewhat special with regards to enabling/disabling (they seem to be
	 * enabled by default with a fixed RQID), let's do the same here.
	 */
	if (tc == 0x08)
		return 0x0001;

	/* Default path: Set RQID = TC. */
#endif
	return tc;
}

static inline int ssh_tc_to_event(u8 tc)
{
	return ssh_rqid_to_event(ssh_tc_to_rqid(tc));
}

static inline u8 ssh_channel_to_index(u8 channel)
{
	return channel - 1u;
}

static inline bool ssh_channel_is_valid(u8 channel)
{
	return ssh_channel_to_index(channel) < SURFACE_SAM_SSH_NUM_CHANNELS;
}


/* -- Safe counters. -------------------------------------------------------- */

struct ssh_seq_counter {
	u8 value;
};

struct ssh_rqid_counter {
	u16 value;
};

static inline void ssh_seq_reset(struct ssh_seq_counter *c)
{
	WRITE_ONCE(c->value, 0);
}

static inline u8 ssh_seq_next(struct ssh_seq_counter *c)
{
	u8 old = READ_ONCE(c->value);
	u8 new = old + 1;
	u8 ret;

	while (unlikely((ret = cmpxchg(&c->value, old, new)) != old)) {
		old = ret;
		new = old + 1;
	}

	return old;
}

static inline void ssh_rqid_reset(struct ssh_rqid_counter *c)
{
	WRITE_ONCE(c->value, 0);
}

static inline u16 ssh_rqid_next(struct ssh_rqid_counter *c)
{
	u16 old = READ_ONCE(c->value);
	u16 new = __ssh_rqid_next(old);
	u16 ret;

	while (unlikely((ret = cmpxchg(&c->value, old, new)) != old)) {
		old = ret;
		new = __ssh_rqid_next(old);
	}

	return old;
}


/* -- Builder functions for SAM-over-SSH messages. -------------------------- */

struct msgbuf {
	u8 *buffer;
	u8 *end;
	u8 *ptr;
};

static inline void msgb_init(struct msgbuf *msgb, u8 *buffer, size_t cap)
{
	msgb->buffer = buffer;
	msgb->end = buffer + cap;
	msgb->ptr = buffer;
}

static inline int msgb_alloc(struct msgbuf *msgb, size_t cap, gfp_t flags)
{
	u8 *buf;

	buf = kzalloc(cap, flags);
	if (!buf)
		return -ENOMEM;

	msgb_init(msgb, buf, cap);
	return 0;
}

static inline void msgb_free(struct msgbuf *msgb)
{
	kfree(msgb->buffer);
	msgb->buffer = NULL;
	msgb->end = NULL;
	msgb->ptr = NULL;
}

static inline void msgb_reset(struct msgbuf *msgb)
{
	msgb->ptr = msgb->buffer;
}

static inline size_t msgb_bytes_used(const struct msgbuf *msgb)
{
	return msgb->ptr - msgb->buffer;
}

static inline void msgb_push_u16(struct msgbuf *msgb, u16 value)
{
	WARN_ON(msgb->ptr + sizeof(u16) > msgb->end);
	if (msgb->ptr + sizeof(u16) > msgb->end)
		return;

	put_unaligned_le16(value, msgb->ptr);
	msgb->ptr += sizeof(u16);
}

static inline void msgb_push_syn(struct msgbuf *msgb)
{
	msgb_push_u16(msgb, SSH_MSG_SYN);
}

static inline void msgb_push_buf(struct msgbuf *msgb, const u8 *buf, size_t len)
{
	msgb->ptr = memcpy(msgb->ptr, buf, len) + len;
}

static inline void msgb_push_crc(struct msgbuf *msgb, const u8 *buf, size_t len)
{
	msgb_push_u16(msgb, ssh_crc(buf, len));
}

static inline void msgb_push_frame(struct msgbuf *msgb, u8 ty, u16 len, u8 seq)
{
	struct ssh_frame *frame = (struct ssh_frame *)msgb->ptr;
	const u8 *const begin = msgb->ptr;

	WARN_ON(msgb->ptr + sizeof(*frame) > msgb->end);
	if (msgb->ptr + sizeof(*frame) > msgb->end)
		return;

	frame->type = ty;
	put_unaligned_le16(len, &frame->len);
	frame->seq  = seq;

	msgb->ptr += sizeof(*frame);
	msgb_push_crc(msgb, begin, msgb->ptr - begin);
}

static inline void msgb_push_ack(struct msgbuf *msgb, u8 seq)
{
	// SYN
	msgb_push_syn(msgb);

	// ACK-type frame + CRC
	msgb_push_frame(msgb, SSH_FRAME_TYPE_ACK, 0x00, seq);

	// payload CRC (ACK-type frames do not have a payload)
	msgb_push_crc(msgb, msgb->ptr, 0);
}

static inline void msgb_push_nak(struct msgbuf *msgb)
{
	// SYN
	msgb_push_syn(msgb);

	// NAK-type frame + CRC
	msgb_push_frame(msgb, SSH_FRAME_TYPE_NAK, 0x00, 0x00);

	// payload CRC (ACK-type frames do not have a payload)
	msgb_push_crc(msgb, msgb->ptr, 0);
}

static inline void msgb_push_cmd(struct msgbuf *msgb, u8 seq,
				 const struct surface_sam_ssh_rqst *rqst,
				 u16 rqid)
{
	struct ssh_command *cmd;
	const u8 *cmd_begin;
	const u8 type = SSH_FRAME_TYPE_DATA_SEQ;

	// SYN
	msgb_push_syn(msgb);

	// command frame + crc
	msgb_push_frame(msgb, type, sizeof(*cmd) + rqst->cdl, seq);

	// frame payload: command struct + payload
	WARN_ON(msgb->ptr + sizeof(*cmd) > msgb->end);
	if (msgb->ptr + sizeof(*cmd) > msgb->end)
		return;

	cmd_begin = msgb->ptr;
	cmd = (struct ssh_command *)msgb->ptr;

	cmd->type    = SSH_PLD_TYPE_CMD;
	cmd->tc      = rqst->tc;
	cmd->chn_out = rqst->chn;
	cmd->chn_in  = 0x00;
	cmd->iid     = rqst->iid;
	put_unaligned_le16(rqid, &cmd->rqid);
	cmd->cid     = rqst->cid;

	msgb->ptr += sizeof(*cmd);

	// command payload
	msgb_push_buf(msgb, rqst->pld, rqst->cdl);

	// crc for command struct + payload
	msgb_push_crc(msgb, cmd_begin, msgb->ptr - cmd_begin);
}


/* -- Parser functions and utilities for SAM-over-SSH messages. ------------- */

struct sshp_buf {
	u8    *ptr;
	size_t len;
	size_t cap;
};


static inline bool sshp_validate_crc(const struct sshp_span *src, const u8 *crc)
{
	u16 actual = ssh_crc(src->ptr, src->len);
	u16 expected = get_unaligned_le16(crc);

	return actual == expected;
}

static bool sshp_find_syn(const struct sshp_span *src, struct sshp_span *rem)
{
	size_t i;

	for (i = 0; i < src->len - 1; i++) {
		if (likely(get_unaligned_le16(src->ptr + i) == SSH_MSG_SYN)) {
			rem->ptr = src->ptr + i;
			rem->len = src->len - i;
			return true;
		}
	}

	if (unlikely(src->ptr[src->len - 1] == (SSH_MSG_SYN & 0xff))) {
		rem->ptr = src->ptr + src->len - 1;
		rem->len = 1;
		return false;
	} else {
		rem->ptr = src->ptr + src->len;
		rem->len = 0;
		return false;
	}
}

static bool sshp_starts_with_syn(const struct sshp_span *src)
{
	return src->len >= 2 && get_unaligned_le16(src->ptr) == SSH_MSG_SYN;
}

static int sshp_parse_frame(const struct device *dev,
			    const struct sshp_span *source,
			    struct ssh_frame **frame,
			    struct sshp_span *payload,
			    size_t maxlen)
{
	struct sshp_span sf;
	struct sshp_span sp;

	// initialize output
	*frame = NULL;
	payload->ptr = NULL;
	payload->len = 0;

	if (!sshp_starts_with_syn(source)) {
		dev_warn(dev, "rx: parser: invalid start of frame\n");
		return -ENOMSG;
	}

	// check for minumum packet length
	if (unlikely(source->len < SSH_MESSAGE_LENGTH(0))) {
		dev_dbg(dev, "rx: parser: not enough data for frame\n");
		return 0;
	}

	// pin down frame
	sf.ptr = source->ptr + sizeof(u16);
	sf.len = sizeof(struct ssh_frame);

	// validate frame CRC
	if (unlikely(!sshp_validate_crc(&sf, sf.ptr + sf.len))) {
		dev_warn(dev, "rx: parser: invalid frame CRC\n");
		return -EBADMSG;
	}

	// ensure packet does not exceed maximum length
	if (unlikely(((struct ssh_frame *)sf.ptr)->len > maxlen)) {
		dev_warn(dev, "rx: parser: frame too large: %u bytes\n",
			 ((struct ssh_frame *)sf.ptr)->len);
		return -EMSGSIZE;
	}

	// pin down payload
	sp.ptr = sf.ptr + sf.len + sizeof(u16);
	sp.len = get_unaligned_le16(&((struct ssh_frame *)sf.ptr)->len);

	// check for frame + payload length
	if (source->len < SSH_MESSAGE_LENGTH(sp.len)) {
		dev_dbg(dev, "rx: parser: not enough data for payload\n");
		return 0;
	}

	// validate payload crc
	if (unlikely(!sshp_validate_crc(&sp, sp.ptr + sp.len))) {
		dev_warn(dev, "rx: parser: invalid payload CRC\n");
		return -EBADMSG;
	}

	*frame = (struct ssh_frame *)sf.ptr;
	*payload = sp;

	dev_dbg(dev, "rx: parser: valid frame found (type: 0x%02x, len: %u)\n",
		(*frame)->type, (*frame)->len);

	return 0;
}

static int sshp_parse_command(const struct device *dev,
			      const struct sshp_span *source,
			      struct ssh_command **command,
			      struct sshp_span *command_data)
{
	// check for minimum length
	if (unlikely(source->len < sizeof(struct ssh_command))) {
		*command = NULL;
		command_data->ptr = NULL;
		command_data->len = 0;

		dev_err(dev, "rx: parser: command payload is too short\n");
		return -ENOMSG;
	}

	*command = (struct ssh_command *)source->ptr;
	command_data->ptr = source->ptr + sizeof(struct ssh_command);
	command_data->len = source->len - sizeof(struct ssh_command);

	dev_dbg(dev, "rx: parser: valid command found (tc: 0x%02x,"
		" cid: 0x%02x)\n", (*command)->tc, (*command)->cid);

	return 0;
}


static inline void sshp_buf_init(struct sshp_buf *buf, u8 *ptr, size_t cap)
{
	buf->ptr = ptr;
	buf->len = 0;
	buf->cap = cap;
}

static inline int sshp_buf_alloc(struct sshp_buf *buf, size_t cap, gfp_t flags)
{
	u8 *ptr;

	ptr = kzalloc(cap, flags);
	if (!ptr)
		return -ENOMEM;

	sshp_buf_init(buf, ptr, cap);
	return 0;

}

static inline void sshp_buf_free(struct sshp_buf *buf)
{
	kfree(buf->ptr);
	buf->ptr = NULL;
	buf->len = 0;
	buf->cap = 0;
}

static inline void sshp_buf_reset(struct sshp_buf *buf)
{
	buf->len = 0;
}

static inline void sshp_buf_drop(struct sshp_buf *buf, size_t n)
{
	memmove(buf->ptr, buf->ptr + n, buf->len - n);
	buf->len -= n;
}

static inline size_t sshp_buf_read_from_fifo(struct sshp_buf *buf,
					     struct kfifo *fifo)
{
	size_t n;

	n =  kfifo_out(fifo, buf->ptr + buf->len, buf->cap - buf->len);
	buf->len += n;

	return n;
}

static inline void sshp_buf_span_from(struct sshp_buf *buf, size_t offset,
				      struct sshp_span *span)
{
	span->ptr = buf->ptr + offset;
	span->len = buf->len - offset;
}


/* -- Packet transport layer (ptl). ----------------------------------------- */
/*
 * To simplify reasoning about the code below, we define a few concepts. The
 * system below is similar to a state-machine for packets, however, there are
 * too many states to explicitly write them down. To (somewhat) manage the
 * states and packets we rely on flags, reference counting, and some simple
 * concepts. State transitions are triggered by actions.
 *
 * >> Actions <<
 *
 * - submit
 * - transmission start (process next item in queue)
 * - transmission finished (guaranteed to never be parallel to transmission
 *   start)
 * - ACK received
 * - NAK received (this is equivalent to issuing re-submit for all pending
 *   packets)
 * - timeout (this is equivalent to re-issuing a submit or canceling)
 * - cancel (non-pending and pending)
 *
 * >> Data Structures, Packet Ownership, General Overview <<
 *
 * The code below employs two main data structures: The packet queue, containing
 * all packets scheduled for transmission, and the set of pending packets,
 * containing all packets awaiting an ACK.
 *
 * Shared ownership of a packet is controlled via reference counting. Inside the
 * transmission system are a total of five packet owners:
 *
 * - the packet queue,
 * - the pending set,
 * - the transmitter thread,
 * - the receiver thread (via ACKing), and
 * - the timeout work item.
 *
 * Normal operation is as follows: The initial reference of the packet is
 * obtained by submitting the packet and queueing it. The receiver thread
 * takes packets from the queue. By doing this, it does not increment the
 * refcount but takes over the reference (removing it from the queue).
 * If the packet is sequenced (i.e. needs to be ACKed by the client), the
 * transmitter thread sets-up the timeout and adds the packet to the pending set
 * before starting to transmit it. As the timeout is handled by a reaper task,
 * no additional reference for it is needed. After the transmit is done, the
 * reference hold by the transmitter thread is dropped. If the packet is
 * unsequenced (i.e. does not need an ACK), the packet is completed by the
 * transmitter thread before dropping that reference.
 *
 * On receial of an ACK, the receiver thread removes and obtains the refernce to
 * the packet from the pending set. On succes, the receiver thread will then
 * complete the packet and drop its reference.
 *
 * On error, the completion callback is immediately run by on thread on which
 * the error was detected.
 *
 * To ensure that a packet eventually leaves the system it is marked as "locked"
 * directly before it is going to be completed or when it is canceled. Marking a
 * packet as "locked" has the effect that passing and creating new references
 * of the packet will be blocked. This means that the packet cannot be added
 * to the queue, the pending set, and the timeout, or be picked up by the
 * transmitter thread or receiver thread. To remove a packet from the system it
 * has to be marked as locked and subsequently all references from the data
 * structures (queue, pending) have to be removed. References held by threads
 * will eventually be dropped automatically as their execution progresses.
 *
 * Note that the packet completion callback is, in case of success and for a
 * sequenced packet, guaranteed to run on the receiver thread, thus providing a
 * way to reliably identify responses to the packet. The packet completion
 * callback is only run once and it does not indicate that the packet has fully
 * left the system. In case of re-submission (and with somewhat unlikely
 * timing), it may be possible that the packet is being re-transmitted while the
 * completion callback runs. Completion will occur both on success and internal
 * error, as well as when the packet is canceled.
 *
 * >> Flags <<
 *
 * Flags are used to indicate the state and progression of a packet. Some flags
 * have stricter guarantees than other:
 *
 * - locked
 *   Indicates if the packet is locked. If the packet is locked, passing and/or
 *   creating additional references to the packet is forbidden. The packet thus
 *   may not be queued, dequeued, or removed or added to the pending set. Note
 *   that the packet state flags may still change (e.g. it may be marked as
 *   ACKed, transmitted, ...).
 *
 * - completed
 *   Indicates if the packet completion has been run or is about to be run. This
 *   flag is used to ensure that the packet completion callback is only run
 *   once.
 *
 * - queued
 *   Indicates if a packet is present in the submission queue or not. This flag
 *   must only be modified with the queue lock held, and must be coherent
 *   presence of the packet in the queue.
 *
 * - pending
 *   Indicates if a packet is present in the set of pending packets or not.
 *   This flag must only be modified with the pending lock held, and must be
 *   coherent presence of the packet in the pending set.
 *
 * - transmitting
 *   Indicates if the packet is currently transmitting. In case of
 *   re-transmissions, it is only safe to wait on the "transmitted" completion
 *   after this flag has been set. The completion will be set both in success
 *   and error case.
 *
 * - transmitted
 *   Indicates if the packet has been transmitted. This flag is not cleared by
 *   the system, thus it indicates the first transmission only.
 *
 * - acked
 *   Indicates if the packet has been acknowledged by the client. There are no
 *   other guarantees given. For example, the packet may still be canceled
 *   and/or the completion may be triggered an error even though this bit is
 *   set. Rely on the status provided by completion instead.
 *
 * - canceled
 *   Indicates if the packet has been canceled from the outside. There are no
 *   other guarantees given. Specifically, the packet may be completed by
 *   another part of the system before the cancellation attempts to complete it.
 *
 * >> General Notes <<
 *
 * To avoid deadlocks, if both queue and pending locks are required, the pending
 * lock must be acquired before the queue lock.
 */

/**
 * Maximum number transmission attempts per sequenced packet in case of
 * time-outs. Must be smaller than 16.
 */
#define SSH_PTL_MAX_PACKET_TRIES	3

/**
 * Timeout as ktime_t delta for ACKs. If we have not received an ACK in this
 * time-frame after starting transmission, the packet will be re-submitted.
 */
#define SSH_PTL_PACKET_TIMEOUT			ms_to_ktime(1000)

/**
 * Maximum time resolution for timeouts. Currently set to max(2 jiffies, 50ms).
 * Should be larger than one jiffy to avoid direct re-scheduling of reaper
 * work_struct.
 */
#define SSH_PTL_PACKET_TIMEOUT_RESOLUTION	ms_to_ktime(max(2000 / HZ, 50))

/**
 * Maximum number of sequenced packets concurrently waiting for an ACK.
 * Packets marked as blocking will not be transmitted while this limit is
 * reached.
 */
#define SSH_PTL_MAX_PENDING		1

#define SSH_PTL_RX_BUF_LEN		4096

#define SSH_PTL_RX_FIFO_LEN		4096


enum ssh_ptl_state_flags {
	SSH_PTL_SF_SHUTDOWN_BIT,
};

struct ssh_ptl_ops {
	void (*data_received)(struct ssh_ptl *p, const struct sshp_span *data);
};

struct ssh_ptl {
	struct serdev_device *serdev;
	unsigned long state;

	struct {
		spinlock_t lock;
		struct list_head head;
	} queue;

	struct {
		spinlock_t lock;
		struct list_head head;
		atomic_t count;
	} pending;

	struct {
		bool thread_signal;
		struct task_struct *thread;
		struct wait_queue_head thread_wq;
		struct wait_queue_head packet_wq;
		struct ssh_packet *packet;
		size_t offset;
	} tx;

	struct {
		struct task_struct *thread;
		struct wait_queue_head wq;
		struct kfifo fifo;
		struct sshp_buf buf;

		struct {
			u16 seqs[8];
			u16 offset;
		} blacklist;
	} rx;

	struct {
		ktime_t timeout;
		ktime_t expires;
		struct delayed_work reaper;
	} rtx_timeout;

	struct ssh_ptl_ops ops;
};


#define __ssam_prcond(func, p, fmt, ...)		\
	do {						\
		if ((p))				\
			func((p), fmt, ##__VA_ARGS__);	\
	} while (0);

#define ptl_dbg(p, fmt, ...)  dev_dbg(&(p)->serdev->dev, fmt, ##__VA_ARGS__)
#define ptl_info(p, fmt, ...) dev_info(&(p)->serdev->dev, fmt, ##__VA_ARGS__)
#define ptl_warn(p, fmt, ...) dev_warn(&(p)->serdev->dev, fmt, ##__VA_ARGS__)
#define ptl_err(p, fmt, ...)  dev_err(&(p)->serdev->dev, fmt, ##__VA_ARGS__)
#define ptl_dbg_cond(p, fmt, ...) __ssam_prcond(ptl_dbg, p, fmt, ##__VA_ARGS__)

#define to_ssh_packet(ptr, member) \
	container_of(ptr, struct ssh_packet, member)

#define to_ssh_ptl(ptr, member) \
	container_of(ptr, struct ssh_ptl, member)


#ifdef CONFIG_SURFACE_SAM_SSH_ERROR_INJECTION

/**
 * ssh_ptl_should_drop_ack_packet - error injection hook to drop ACK packets
 *
 * Useful to test detection and handling of automated re-transmits by the EC.
 * Specifically of packets that the EC consideres not-ACKed but the driver
 * already consideres ACKed (due to dropped ACK). In this case, the EC
 * re-transmits the packet-to-be-ACKed and the driver should detect it as
 * duplicate/already handled. Note that the driver should still send an ACK
 * for the re-transmitted packet.
 */
static noinline bool ssh_ptl_should_drop_ack_packet(void)
{
	return false;
}
ALLOW_ERROR_INJECTION(ssh_ptl_should_drop_ack_packet, TRUE);

/**
 * ssh_ptl_should_drop_nak_packet - error injection hook to drop NAK packets
 *
 * Useful to test/force automated (timeout-based) re-transmit by the EC.
 * Specifically, packets that have not reached the driver completely/with valid
 * checksums. Only useful in combination with receival of (injected) bad data.
 */
static noinline bool ssh_ptl_should_drop_nak_packet(void)
{
	return false;
}
ALLOW_ERROR_INJECTION(ssh_ptl_should_drop_nak_packet, TRUE);

/**
 * ssh_ptl_should_drop_dsq_packet - error injection hook to drop sequenced data
 * packet
 *
 * Useful to test re-transmit timeout of the driver. If the data packet has not
 * been ACKed after a certain time, the driver should re-transmit the packet up
 * to limited number of times defined in SSH_PTL_MAX_PACKET_TRIES.
 */
static noinline bool ssh_ptl_should_drop_dsq_packet(void)
{
	return false;
}
ALLOW_ERROR_INJECTION(ssh_ptl_should_drop_dsq_packet, TRUE);

/**
 * ssh_ptl_should_fail_write - error injection hook to make serdev_device_write
 * fail
 *
 * Hook to simulate errors in serdev_device_write when transmitting packets.
 */
static noinline int ssh_ptl_should_fail_write(void)
{
	return 0;
}
ALLOW_ERROR_INJECTION(ssh_ptl_should_fail_write, ERRNO);

/**
 * ssh_ptl_should_corrupt_tx_data - error injection hook to simualte invalid
 * data being sent to the EC
 *
 * Hook to simulate corrupt/invalid data being sent from host (driver) to EC.
 * Causes the package data to be actively corrupted by overwriting it with
 * pre-defined values, such that it becomes invalid, causing the EC to respond
 * with a NAK packet. Useful to test handling of NAK packets received by the
 * driver.
 */
static noinline bool ssh_ptl_should_corrupt_tx_data(void)
{
	return false;
}
ALLOW_ERROR_INJECTION(ssh_ptl_should_corrupt_tx_data, TRUE);

/**
 * ssh_ptl_should_corrupt_rx_syn - error injection hook to simulate invalid
 * data being sent by the EC
 *
 * Hook to simulate invalid SYN bytes, i.e. an invalid start of messages and
 * test handling thereof in the driver.
 */
static noinline bool ssh_ptl_should_corrupt_rx_syn(void)
{
	return false;
}
ALLOW_ERROR_INJECTION(ssh_ptl_should_corrupt_rx_syn, TRUE);

/**
 * ssh_ptl_should_corrupt_rx_data - error injection hook to simulate invalid
 * data being sent by the EC
 *
 * Hook to simulate invalid data/checksum of the message frame and test handling
 * thereof in the driver.
 */
static noinline bool ssh_ptl_should_corrupt_rx_data(void)
{
	return false;
}
ALLOW_ERROR_INJECTION(ssh_ptl_should_corrupt_rx_data, TRUE);


static inline bool __ssh_ptl_should_drop_ack_packet(struct ssh_packet *packet)
{
	if (likely(!ssh_ptl_should_drop_ack_packet()))
		return false;

	trace_ssam_ei_tx_drop_ack_packet(packet);
	ptl_info(packet->ptl, "packet error injection: dropping ACK packet %p\n",
		 packet);

	return true;
}

static inline bool __ssh_ptl_should_drop_nak_packet(struct ssh_packet *packet)
{
	if (likely(!ssh_ptl_should_drop_nak_packet()))
		return false;

	trace_ssam_ei_tx_drop_nak_packet(packet);
	ptl_info(packet->ptl, "packet error injection: dropping NAK packet %p\n",
		 packet);

	return true;
}

static inline bool __ssh_ptl_should_drop_dsq_packet(struct ssh_packet *packet)
{
	if (likely(!ssh_ptl_should_drop_dsq_packet()))
		return false;

	trace_ssam_ei_tx_drop_dsq_packet(packet);
	ptl_info(packet->ptl,
		"packet error injection: dropping sequenced data packet %p\n",
		 packet);

	return true;
}

static bool ssh_ptl_should_drop_packet(struct ssh_packet *packet)
{
	// ignore packets that don't carry any data (i.e. flush)
	if (!packet->data || !packet->data_length)
		return false;

	switch (packet->data[SSH_MSGOFFSET_FRAME(type)]) {
	case SSH_FRAME_TYPE_ACK:
		return __ssh_ptl_should_drop_ack_packet(packet);

	case SSH_FRAME_TYPE_NAK:
		return __ssh_ptl_should_drop_nak_packet(packet);

	case SSH_FRAME_TYPE_DATA_SEQ:
		return __ssh_ptl_should_drop_dsq_packet(packet);

	default:
		return false;
	}
}

static inline int ssh_ptl_write_buf(struct ssh_ptl *ptl,
				    struct ssh_packet *packet,
				    const unsigned char *buf,
				    size_t count)
{
	int status;

	status = ssh_ptl_should_fail_write();
	if (unlikely(status)) {
		trace_ssam_ei_tx_fail_write(packet, status);
		ptl_info(packet->ptl,
			 "packet error injection: simulating transmit error %d, packet %p\n",
			 status, packet);

		return status;
	}

	return serdev_device_write_buf(ptl->serdev, buf, count);
}

static inline void ssh_ptl_tx_inject_invalid_data(struct ssh_packet *packet)
{
	// ignore packets that don't carry any data (i.e. flush)
	if (!packet->data || !packet->data_length)
		return;

	// only allow sequenced data packets to be modified
	if (packet->data[SSH_MSGOFFSET_FRAME(type)] != SSH_FRAME_TYPE_DATA_SEQ)
		return;

	if (likely(!ssh_ptl_should_corrupt_tx_data()))
		return;

	trace_ssam_ei_tx_corrupt_data(packet);
	ptl_info(packet->ptl,
		 "packet error injection: simulating invalid transmit data on packet %p\n",
		 packet);

	/*
	 * NB: The value 0xb3 has been chosen more or less randomly so that it
	 * doesn't have any (major) overlap with the SYN bytes (aa 55) and is
	 * non-trivial (i.e. non-zero, non-0xff).
	 */
	memset(packet->data, 0xb3, packet->data_length);
}

static inline void ssh_ptl_rx_inject_invalid_syn(struct ssh_ptl *ptl,
						 struct sshp_span *data)
{
	struct sshp_span frame;

	// check if there actually is something to corrupt
	if (!sshp_find_syn(data, &frame))
		return;

	if (likely(!ssh_ptl_should_corrupt_rx_syn()))
		return;

	trace_ssam_ei_rx_corrupt_syn("data_length", data->len);

	data->ptr[1] = 0xb3;	// set second byte of SYN to "random" value
}

static inline void ssh_ptl_rx_inject_invalid_data(struct ssh_ptl *ptl,
						  struct sshp_span *frame)
{
	size_t payload_len, message_len;
	struct ssh_frame *sshf;

	// ignore incomplete messages, will get handled once it's complete
	if (frame->len < SSH_MESSAGE_LENGTH(0))
		return;

	// ignore incomplete messages, part 2
	payload_len = get_unaligned_le16(&frame->ptr[SSH_MSGOFFSET_FRAME(len)]);
	message_len = SSH_MESSAGE_LENGTH(payload_len);
	if (frame->len < message_len)
		return;

	if (likely(!ssh_ptl_should_corrupt_rx_data()))
		return;

	sshf = (struct ssh_frame *)&frame->ptr[SSH_MSGOFFSET_FRAME(type)];
	trace_ssam_ei_rx_corrupt_data(sshf);

	/*
	 * Flip bits in first byte of payload checksum. This is basically
	 * equivalent to a payload/frame data error without us having to worry
	 * about (the, arguably pretty small, probability of) accidental
	 * checksum collisions.
	 */
	frame->ptr[frame->len - 2] = ~frame->ptr[frame->len - 2];
}

#else /* CONFIG_SURFACE_SAM_SSH_ERROR_INJECTION */

static inline bool ssh_ptl_should_drop_packet(struct ssh_packet *packet)
{
	return false;
}

static inline int ssh_ptl_write_buf(struct ssh_ptl *ptl,
				    struct ssh_packet *packet,
				    const unsigned char *buf,
				    size_t count)
{
	return serdev_device_write_buf(ptl->serdev, buf, count);
}

static inline void ssh_ptl_tx_inject_invalid_data(struct ssh_packet *packet)
{
}

static inline void ssh_ptl_rx_inject_invalid_syn(struct ssh_ptl *ptl,
						 struct sshp_span *data)
{
}

static inline void ssh_ptl_rx_inject_invalid_data(struct ssh_ptl *ptl,
						  struct sshp_span *frame)
{
}

#endif /* CONFIG_SURFACE_SAM_SSH_ERROR_INJECTION */


static void __ssh_ptl_packet_release(struct kref *kref)
{
	struct ssh_packet *p = to_ssh_packet(kref, refcnt);

	trace_ssam_packet_release(p);

	ptl_dbg_cond(p->ptl, "ptl: releasing packet %p\n", p);
	p->ops->release(p);
}

static inline void ssh_packet_get(struct ssh_packet *packet)
{
	kref_get(&packet->refcnt);
}

static inline void ssh_packet_put(struct ssh_packet *packet)
{
	kref_put(&packet->refcnt, __ssh_ptl_packet_release);
}


static inline u8 ssh_packet_get_seq(struct ssh_packet *packet)
{
	return packet->data[SSH_MSGOFFSET_FRAME(seq)];
}


struct ssh_packet_args {
	u8 type;
	u8 priority;
	const struct ssh_packet_ops *ops;
};

static void ssh_packet_init(struct ssh_packet *packet,
			    const struct ssh_packet_args *args)
{
	kref_init(&packet->refcnt);

	packet->ptl = NULL;
	INIT_LIST_HEAD(&packet->queue_node);
	INIT_LIST_HEAD(&packet->pending_node);

	packet->type = args->type;
	packet->priority = args->priority;
	packet->state = 0;
	packet->timestamp = KTIME_MAX;

	packet->data_length = 0;
	packet->data = NULL;

	packet->ops = args->ops;
}


static struct ssh_packet *ptl_alloc_ctrl_packet(
			struct ssh_ptl *ptl, const struct ssh_packet_args *args,
			gfp_t flags)
{
	struct ssh_packet *packet;

	// TODO: chache packets

	packet = kzalloc(sizeof(struct ssh_packet) + SSH_MSG_LEN_CTRL, flags);
	if (!packet)
		return NULL;

	ssh_packet_init(packet, args);
	packet->data_length = SSH_MSG_LEN_CTRL;
	packet->data = ((u8 *) packet) + sizeof(struct ssh_packet);

	return packet;
}

static void ptl_free_ctrl_packet(struct ssh_packet *p)
{
	// TODO: chache packets

	kfree(p);
}

static const struct ssh_packet_ops ssh_ptl_ctrl_packet_ops = {
	.complete = NULL,
	.release = ptl_free_ctrl_packet,
};


static void ssh_ptl_timeout_reaper_mod(struct ssh_ptl *ptl, ktime_t now,
				       ktime_t expires)
{
	unsigned long delta = msecs_to_jiffies(ktime_ms_delta(expires, now));
	ktime_t aexp = ktime_add(expires, SSH_PTL_PACKET_TIMEOUT_RESOLUTION);
	ktime_t old;

	// re-adjust / schedule reaper if it is above resolution delta
	old = READ_ONCE(ptl->rtx_timeout.expires);
	while (ktime_before(aexp, old))
		old = cmpxchg64(&ptl->rtx_timeout.expires, old, expires);

	// if we updated the reaper expiration, modify work timeout
	if (old == expires)
		mod_delayed_work(system_wq, &ptl->rtx_timeout.reaper, delta);
}

static void ssh_ptl_timeout_start(struct ssh_packet *packet)
{
	struct ssh_ptl *ptl = packet->ptl;
	ktime_t timestamp = ktime_get_coarse_boottime();
	ktime_t timeout = ptl->rtx_timeout.timeout;

	if (test_bit(SSH_PACKET_SF_LOCKED_BIT, &packet->state))
		return;

	WRITE_ONCE(packet->timestamp, timestamp);
	smp_mb__after_atomic();

	ssh_ptl_timeout_reaper_mod(packet->ptl, timestamp, timestamp + timeout);
}


static struct list_head *__ssh_ptl_queue_find_entrypoint(struct ssh_packet *p)
{
	struct list_head *head;
	u8 priority = READ_ONCE(p->priority);

	/*
	 * We generally assume that there are less control (ACK/NAK) packets and
	 * re-submitted data packets as there are normal data packets (at least
	 * in situations in which many packets are queued; if there aren't many
	 * packets queued the decision on how to iterate should be basically
	 * irrellevant; the number of control/data packets is more or less
	 * limited via the maximum number of pending packets). Thus, when
	 * inserting a control or re-submitted data packet, (determined by their
	 * priority), we search from front to back. Normal data packets are,
	 * usually queued directly at the tail of the queue, so for those search
	 * from back to front.
	 */

	if (priority > SSH_PACKET_PRIORITY_DATA) {
		list_for_each(head, &p->ptl->queue.head) {
			p = list_entry(head, struct ssh_packet, queue_node);

			if (READ_ONCE(p->priority) < priority)
				break;
		}
	} else {
		list_for_each_prev(head, &p->ptl->queue.head) {
			p = list_entry(head, struct ssh_packet, queue_node);

			if (READ_ONCE(p->priority) >= priority) {
				head = head->next;
				break;
			}
		}
	}


	return head;
}

static int ssh_ptl_queue_push(struct ssh_packet *packet)
{
	struct ssh_ptl *ptl = packet->ptl;
	struct list_head *head;

	spin_lock(&ptl->queue.lock);

	if (test_bit(SSH_PTL_SF_SHUTDOWN_BIT, &ptl->state)) {
		spin_unlock(&ptl->queue.lock);
		return -ESHUTDOWN;
	}

	// avoid further transitions when cancelling/completing
	if (test_bit(SSH_PACKET_SF_LOCKED_BIT, &packet->state)) {
		spin_unlock(&ptl->queue.lock);
		return -EINVAL;
	}

	// if this packet has already been queued, do not add it
	if (test_and_set_bit(SSH_PACKET_SF_QUEUED_BIT, &packet->state)) {
		spin_unlock(&ptl->queue.lock);
		return -EALREADY;
	}

	head = __ssh_ptl_queue_find_entrypoint(packet);

	ssh_packet_get(packet);
	list_add_tail(&packet->queue_node, &ptl->queue.head);

	spin_unlock(&ptl->queue.lock);
	return 0;
}

static void ssh_ptl_queue_remove(struct ssh_packet *packet)
{
	struct ssh_ptl *ptl = packet->ptl;
	bool remove;

	spin_lock(&ptl->queue.lock);

	remove = test_and_clear_bit(SSH_PACKET_SF_QUEUED_BIT, &packet->state);
	if (remove)
		list_del(&packet->queue_node);

	spin_unlock(&ptl->queue.lock);

	if (remove)
		ssh_packet_put(packet);
}


static void ssh_ptl_pending_push(struct ssh_packet *packet)
{
	struct ssh_ptl *ptl = packet->ptl;

	spin_lock(&ptl->pending.lock);

	// if we are cancelling/completing this packet, do not add it
	if (test_bit(SSH_PACKET_SF_LOCKED_BIT, &packet->state)) {
		spin_unlock(&ptl->pending.lock);
		return;
	}

	// in case it is already pending (e.g. re-submission), do not add it
	if (test_and_set_bit(SSH_PACKET_SF_PENDING_BIT, &packet->state)) {
		spin_unlock(&ptl->pending.lock);
		return;
	}

	atomic_inc(&ptl->pending.count);
	ssh_packet_get(packet);
	list_add_tail(&packet->pending_node, &ptl->pending.head);

	spin_unlock(&ptl->pending.lock);
}

static void ssh_ptl_pending_remove(struct ssh_packet *packet)
{
	struct ssh_ptl *ptl = packet->ptl;
	bool remove;

	spin_lock(&ptl->pending.lock);

	remove = test_and_clear_bit(SSH_PACKET_SF_PENDING_BIT, &packet->state);
	if (remove) {
		list_del(&packet->pending_node);
		atomic_dec(&ptl->pending.count);
	}

	spin_unlock(&ptl->pending.lock);

	if (remove)
		ssh_packet_put(packet);
}


static void __ssh_ptl_complete(struct ssh_packet *p, int status)
{
	struct ssh_ptl *ptl = READ_ONCE(p->ptl);

	trace_ssam_packet_complete(p, status);

	ptl_dbg_cond(ptl, "ptl: completing packet %p\n", p);
	if (p->ops->complete)
		p->ops->complete(p, status);
}

static void ssh_ptl_remove_and_complete(struct ssh_packet *p, int status)
{
	/*
	 * A call to this function should in general be preceeded by
	 * set_bit(SSH_PACKET_SF_LOCKED_BIT, &p->flags) to avoid re-adding the
	 * packet to the structures it's going to be removed from.
	 *
	 * The set_bit call does not need explicit memory barriers as the
	 * implicit barrier of the test_and_set_bit call below ensure that the
	 * flag is visible before we actually attempt to remove the packet.
	 */

	if (test_and_set_bit(SSH_PACKET_SF_COMPLETED_BIT, &p->state))
		return;

	ssh_ptl_queue_remove(p);
	ssh_ptl_pending_remove(p);

	__ssh_ptl_complete(p, status);
}


static bool ssh_ptl_tx_can_process(struct ssh_packet *packet)
{
	struct ssh_ptl *ptl = packet->ptl;

	if (packet->type & SSH_PACKET_TY_FLUSH)
		return !atomic_read(&ptl->pending.count);

	// we can alwas process non-blocking packets
	if (!(packet->type & SSH_PACKET_TY_BLOCKING))
		return true;

	// if we are already waiting for this packet, send it again
	if (test_bit(SSH_PACKET_SF_PENDING_BIT, &packet->state))
		return true;

	// otherwise: check if we have the capacity to send
	return atomic_read(&ptl->pending.count) < SSH_PTL_MAX_PENDING;
}

static struct ssh_packet *ssh_ptl_tx_pop(struct ssh_ptl *ptl)
{
	struct ssh_packet *packet = ERR_PTR(-ENOENT);
	struct ssh_packet *p, *n;

	spin_lock(&ptl->queue.lock);
	list_for_each_entry_safe(p, n, &ptl->queue.head, queue_node) {
		/*
		 * If we are cancelling or completing this packet, ignore it.
		 * It's going to be removed from this queue shortly.
		 */
		if (test_bit(SSH_PACKET_SF_LOCKED_BIT, &p->state)) {
			spin_unlock(&ptl->queue.lock);
			continue;
		}

		/*
		 * Packets should be ordered non-blocking/to-be-resent first.
		 * If we cannot process this packet, assume that we can't
		 * process any following packet either and abort.
		 */
		if (!ssh_ptl_tx_can_process(p)) {
			spin_unlock(&ptl->queue.lock);
			packet = ERR_PTR(-EBUSY);
			break;
		}

		/*
		 * We are allowed to change the state now. Remove it from the
		 * queue and mark it as being transmitted. Note that we cannot
		 * add it to the set of pending packets yet, as queue locks must
		 * always be acquired before packet locks (otherwise we might
		 * run into a deadlock).
		 */

		list_del(&p->queue_node);

		/*
		 * Ensure that the "queued" bit gets cleared after setting the
		 * "transmitting" bit to guaranteee non-zero flags.
		 */
		set_bit(SSH_PACKET_SF_TRANSMITTING_BIT, &p->state);
		smp_mb__before_atomic();
		clear_bit(SSH_PACKET_SF_QUEUED_BIT, &p->state);

		packet = p;
		break;
	}
	spin_unlock(&ptl->queue.lock);

	return packet;
}

static struct ssh_packet *ssh_ptl_tx_next(struct ssh_ptl *ptl)
{
	struct ssh_packet *p;

	p = ssh_ptl_tx_pop(ptl);
	if (IS_ERR(p))
		return p;

	if (p->type & SSH_PACKET_TY_SEQUENCED) {
		ptl_dbg(ptl, "ptl: transmitting sequenced packet %p\n", p);
		ssh_ptl_pending_push(p);
		ssh_ptl_timeout_start(p);
	} else {
		ptl_dbg(ptl, "ptl: transmitting non-sequenced packet %p\n", p);
	}

	/*
	 * Update number of tries. This directly influences the priority in case
	 * the packet is re-submitted (e.g. via timeout/NAK). Note that this is
	 * the only place where we update the priority in-flight. As this runs
	 * only on the tx-thread, this read-modify-write procedure is safe.
	 */
	WRITE_ONCE(p->priority, READ_ONCE(p->priority) + 1);

	return p;
}

static void ssh_ptl_tx_compl_success(struct ssh_packet *packet)
{
	struct ssh_ptl *ptl = packet->ptl;

	ptl_dbg(ptl, "ptl: successfully transmitted packet %p\n", packet);

	/*
	 * Transition to state to "transmitted". Ensure that the flags never get
	 * zero with barrier.
	 */
	set_bit(SSH_PACKET_SF_TRANSMITTED_BIT, &packet->state);
	smp_mb__before_atomic();
	clear_bit(SSH_PACKET_SF_TRANSMITTING_BIT, &packet->state);

	// if the packet is unsequenced, we're done: lock and complete
	if (!(packet->type & SSH_PACKET_TY_SEQUENCED)) {
		set_bit(SSH_PACKET_SF_LOCKED_BIT, &packet->state);
		ssh_ptl_remove_and_complete(packet, 0);
	}

	/*
	 * Notify that a packet transmission has finished. In general we're only
	 * waiting for one packet (if any), so wake_up_all should be fine.
	 */
	wake_up_all(&ptl->tx.packet_wq);
}

static void ssh_ptl_tx_compl_error(struct ssh_packet *packet, int status)
{
	/*
	 * Transmission failure: Lock the packet and try to complete it. Ensure
	 * that the flags never get zero with barrier.
	 */
	set_bit(SSH_PACKET_SF_LOCKED_BIT, &packet->state);
	smp_mb__before_atomic();
	clear_bit(SSH_PACKET_SF_TRANSMITTING_BIT, &packet->state);

	ptl_err(packet->ptl, "ptl: transmission error: %d\n", status);
	ptl_dbg(packet->ptl, "ptl: failed to transmit packet: %p\n", packet);

	ssh_ptl_remove_and_complete(packet, status);

	/*
	 * Notify that a packet transmission has finished. In general we're only
	 * waiting for one packet (if any), so wake_up_all should be fine.
	 */
	wake_up_all(&packet->ptl->tx.packet_wq);
}

static void ssh_ptl_tx_threadfn_wait(struct ssh_ptl *ptl)
{
	wait_event_interruptible(ptl->tx.thread_wq,
		READ_ONCE(ptl->tx.thread_signal) || kthread_should_stop());
	WRITE_ONCE(ptl->tx.thread_signal, false);
}

static int ssh_ptl_tx_threadfn(void *data)
{
	struct ssh_ptl *ptl = data;

	while (!kthread_should_stop()) {
		unsigned char *buf;
		bool drop = false;
		size_t len = 0;
		int status = 0;

		// if we don't have a packet, get the next and add it to pending
		if (IS_ERR_OR_NULL(ptl->tx.packet)) {
			ptl->tx.packet = ssh_ptl_tx_next(ptl);
			ptl->tx.offset = 0;

			// if no packet is available, we are done
			if (IS_ERR(ptl->tx.packet)) {
				ssh_ptl_tx_threadfn_wait(ptl);
				continue;
			}
		}

		// error injection: drop packet to simulate transmission problem
		if (ptl->tx.offset == 0)
			drop = ssh_ptl_should_drop_packet(ptl->tx.packet);

		// error injection: simulate invalid packet data
		if (ptl->tx.offset == 0 && !drop)
			ssh_ptl_tx_inject_invalid_data(ptl->tx.packet);

		// flush-packets don't have any data
		if (likely(ptl->tx.packet->data && !drop)) {
			buf = ptl->tx.packet->data + ptl->tx.offset;
			len = ptl->tx.packet->data_length - ptl->tx.offset;

			ptl_dbg(ptl, "tx: sending data (length: %zu)\n", len);
			print_hex_dump_debug("tx: ", DUMP_PREFIX_OFFSET, 16, 1,
					     buf, len, false);

			status = ssh_ptl_write_buf(ptl, ptl->tx.packet, buf, len);
		}

		if (status < 0) {
			// complete packet with error
			ssh_ptl_tx_compl_error(ptl->tx.packet, status);
			ssh_packet_put(ptl->tx.packet);
			ptl->tx.packet = NULL;

		} else if (status == len) {
			// complete packet and/or mark as transmitted
			ssh_ptl_tx_compl_success(ptl->tx.packet);
			ssh_packet_put(ptl->tx.packet);
			ptl->tx.packet = NULL;

		} else {	// need more buffer space
			ptl->tx.offset += status;
			ssh_ptl_tx_threadfn_wait(ptl);
		}
	}

	// cancel active packet before we actually stop
	if (!IS_ERR_OR_NULL(ptl->tx.packet)) {
		ssh_ptl_tx_compl_error(ptl->tx.packet, -ESHUTDOWN);
		ssh_packet_put(ptl->tx.packet);
		ptl->tx.packet = NULL;
	}

	return 0;
}

static inline void ssh_ptl_tx_wakeup(struct ssh_ptl *ptl, bool force)
{
	if (test_bit(SSH_PTL_SF_SHUTDOWN_BIT, &ptl->state))
		return;

	if (force || atomic_read(&ptl->pending.count) < SSH_PTL_MAX_PENDING) {
		WRITE_ONCE(ptl->tx.thread_signal, true);
		smp_mb__after_atomic();
		wake_up(&ptl->tx.thread_wq);
	}
}

static int ssh_ptl_tx_start(struct ssh_ptl *ptl)
{
	ptl->tx.thread = kthread_run(ssh_ptl_tx_threadfn, ptl, "surface-sh-tx");
	if (IS_ERR(ptl->tx.thread))
		return PTR_ERR(ptl->tx.thread);

	return 0;
}

static int ssh_ptl_tx_stop(struct ssh_ptl *ptl)
{
	int status = 0;

	if (ptl->tx.thread) {
		status = kthread_stop(ptl->tx.thread);
		ptl->tx.thread = NULL;
	}

	return status;
}


static struct ssh_packet *ssh_ptl_ack_pop(struct ssh_ptl *ptl, u8 seq_id)
{
	struct ssh_packet *packet = ERR_PTR(-ENOENT);
	struct ssh_packet *p, *n;

	spin_lock(&ptl->pending.lock);
	list_for_each_entry_safe(p, n, &ptl->pending.head, pending_node) {
		/*
		 * We generally expect packets to be in order, so first packet
		 * to be added to pending is first to be sent, is first to be
		 * ACKed.
		 */
		if (unlikely(ssh_packet_get_seq(p) != seq_id))
			continue;

		/*
		 * In case we receive an ACK while handling a transmission error
		 * completion. The packet will be removed shortly.
		 */
		if (unlikely(test_bit(SSH_PACKET_SF_LOCKED_BIT, &p->state))) {
			packet = ERR_PTR(-EPERM);
			break;
		}

		/*
		 * Mark packet as ACKed and remove it from pending. Ensure that
		 * the flags never get zero with barrier.
		 */
		set_bit(SSH_PACKET_SF_ACKED_BIT, &p->state);
		smp_mb__before_atomic();
		clear_bit(SSH_PACKET_SF_PENDING_BIT, &p->state);

		atomic_dec(&ptl->pending.count);
		list_del(&p->pending_node);
		packet = p;

		break;
	}
	spin_unlock(&ptl->pending.lock);

	return packet;
}

static void ssh_ptl_wait_until_transmitted(struct ssh_packet *packet)
{
	wait_event(packet->ptl->tx.packet_wq,
		   test_bit(SSH_PACKET_SF_TRANSMITTED_BIT, &packet->state)
		   || test_bit(SSH_PACKET_SF_LOCKED_BIT, &packet->state));
}

static void ssh_ptl_acknowledge(struct ssh_ptl *ptl, u8 seq)
{
	struct ssh_packet *p;
	int status = 0;

	p = ssh_ptl_ack_pop(ptl, seq);
	if (IS_ERR(p)) {
		if (PTR_ERR(p) == -ENOENT) {
			/*
			 * The packet has not been found in the set of pending
			 * packets.
			 */
			ptl_warn(ptl, "ptl: received ACK for non-pending"
				 " packet\n");
		} else {
			/*
			 * The packet is pending, but we are not allowed to take
			 * it because it has been locked.
			 */
		}
		return;
	}

	ptl_dbg(ptl, "ptl: received ACK for packet %p\n", p);

	/*
	 * It is possible that the packet has been transmitted, but the state
	 * has not been updated from "transmitting" to "transmitted" yet.
	 * In that case, we need to wait for this transition to occur in order
	 * to determine between success or failure.
	 */
	if (test_bit(SSH_PACKET_SF_TRANSMITTING_BIT, &p->state))
		ssh_ptl_wait_until_transmitted(p);

	/*
	 * The packet will already be locked in case of a transmission error or
	 * cancellation. Let the transmitter or cancellation issuer complete the
	 * packet.
	 */
	if (unlikely(test_and_set_bit(SSH_PACKET_SF_LOCKED_BIT, &p->state))) {
		ssh_packet_put(p);
		return;
	}

	if (unlikely(!test_bit(SSH_PACKET_SF_TRANSMITTED_BIT, &p->state))) {
		ptl_err(ptl, "ptl: received ACK before packet had been fully"
			" transmitted\n");
		status = -EREMOTEIO;
	}

	ssh_ptl_remove_and_complete(p, status);
	ssh_packet_put(p);

	ssh_ptl_tx_wakeup(ptl, false);
}


static int ssh_ptl_submit(struct ssh_ptl *ptl, struct ssh_packet *packet)
{
	int status;

	trace_ssam_packet_submit(packet);

	// validate packet fields
	if (packet->type & SSH_PACKET_TY_FLUSH) {
		if (packet->data || (packet->type & SSH_PACKET_TY_SEQUENCED))
			return -EINVAL;
	} else if (!packet->data) {
		return -EINVAL;
	}

	/*
	 * This function is currently not intended for re-submission. The ptl
	 * reference only gets set on the first submission. After the first
	 * submission, it has to be read-only.
	 *
	 * Use cmpxchg to ensure safety with regards to ssh_ptl_cancel and
	 * re-entry, where we can't guarantee that the packet has been submitted
	 * yet.
	 *
	 * The implicit barrier of cmpxchg is paired with barrier in
	 * ssh_ptl_cancel to guarantee cancelation in case the packet has never
	 * been submitted or is currently being submitted.
	 */
	if (cmpxchg(&packet->ptl, NULL, ptl) != NULL)
		return -EALREADY;

	status = ssh_ptl_queue_push(packet);
	if (status)
		return status;

	ssh_ptl_tx_wakeup(ptl, !(packet->type & SSH_PACKET_TY_BLOCKING));
	return 0;
}

static void __ssh_ptl_resubmit(struct ssh_packet *packet)
{
	struct list_head *head;

	trace_ssam_packet_resubmit(packet);

	spin_lock(&packet->ptl->queue.lock);

	// if this packet has already been queued, do not add it
	if (test_and_set_bit(SSH_PACKET_SF_QUEUED_BIT, &packet->state)) {
		spin_unlock(&packet->ptl->queue.lock);
		return;
	}

	// find first node with lower priority
	head = __ssh_ptl_queue_find_entrypoint(packet);

	WRITE_ONCE(packet->timestamp, KTIME_MAX);
	smp_mb__after_atomic();

	// add packet
	ssh_packet_get(packet);
	list_add_tail(&packet->queue_node, head);

	spin_unlock(&packet->ptl->queue.lock);
}

static void ssh_ptl_resubmit_pending(struct ssh_ptl *ptl)
{
	struct ssh_packet *p;
	bool resub = false;
	u8 try;

	/*
	 * Note: We deliberately do not remove/attempt to cancel and complete
	 * packets that are out of tires in this function. The packet will be
	 * eventually canceled and completed by the timeout. Removing the packet
	 * here could lead to overly eager cancelation if the packet has not
	 * been re-transmitted yet but the tries-counter already updated (i.e
	 * ssh_ptl_tx_next removed the packet from the queue and updated the
	 * counter, but re-transmission for the last try has not actually
	 * started yet).
	 */

	spin_lock(&ptl->pending.lock);

	// re-queue all pending packets
	list_for_each_entry(p, &ptl->pending.head, pending_node) {
		// avoid further transitions if locked
		if (test_bit(SSH_PACKET_SF_LOCKED_BIT, &p->state))
			continue;

		// do not re-schedule if packet is out of tries
		try = ssh_packet_priority_get_try(READ_ONCE(p->priority));
		if (try >= SSH_PTL_MAX_PACKET_TRIES)
			continue;

		resub = true;
		__ssh_ptl_resubmit(p);
	}

	spin_unlock(&ptl->pending.lock);

	ssh_ptl_tx_wakeup(ptl, resub);
}

static void ssh_ptl_cancel(struct ssh_packet *p)
{
	if (test_and_set_bit(SSH_PACKET_SF_CANCELED_BIT, &p->state))
		return;

	trace_ssam_packet_cancel(p);

	/*
	 * Lock packet and commit with memory barrier. If this packet has
	 * already been locked, it's going to be removed and completed by
	 * another party, which should have precedence.
	 */
	if (test_and_set_bit(SSH_PACKET_SF_LOCKED_BIT, &p->state))
		return;

	/*
	 * By marking the packet as locked and employing the implicit memory
	 * barrier of test_and_set_bit, we have guaranteed that, at this point,
	 * the packet cannot be added to the queue any more.
	 *
	 * In case the packet has never been submitted, packet->ptl is NULL. If
	 * the packet is currently being submitted, packet->ptl may be NULL or
	 * non-NULL. Due marking the packet as locked above and committing with
	 * the memory barrier, we have guaranteed that, if packet->ptl is NULL,
	 * the packet will never be added to the queue. If packet->ptl is
	 * non-NULL, we don't have any guarantees.
	 */

	if (READ_ONCE(p->ptl)) {
		ssh_ptl_remove_and_complete(p, -ECANCELED);
		ssh_ptl_tx_wakeup(p->ptl, false);
	} else if (!test_and_set_bit(SSH_PACKET_SF_COMPLETED_BIT, &p->state)) {
		__ssh_ptl_complete(p, -ECANCELED);
	}
}


static ktime_t ssh_packet_get_expiration(struct ssh_packet *p, ktime_t timeout)
{
	ktime_t timestamp = READ_ONCE(p->timestamp);

	if (timestamp != KTIME_MAX)
		return ktime_add(timestamp, timeout);
	else
		return KTIME_MAX;
}

static void ssh_ptl_timeout_reap(struct work_struct *work)
{
	struct ssh_ptl *ptl = to_ssh_ptl(work, rtx_timeout.reaper.work);
	struct ssh_packet *p, *n;
	LIST_HEAD(claimed);
	ktime_t now = ktime_get_coarse_boottime();
	ktime_t timeout = ptl->rtx_timeout.timeout;
	ktime_t next = KTIME_MAX;
	bool resub = false;

	trace_ssam_ptl_timeout_reap("pending", atomic_read(&ptl->pending.count));

	/*
	 * Mark reaper as "not pending". This is done before checking any
	 * packets to avoid lost-update type problems.
	 */
	WRITE_ONCE(ptl->rtx_timeout.expires, KTIME_MAX);
	smp_mb__after_atomic();

	spin_lock(&ptl->pending.lock);

	list_for_each_entry_safe(p, n, &ptl->pending.head, pending_node) {
		ktime_t expires = ssh_packet_get_expiration(p, timeout);
		u8 try;

		/*
		 * Check if the timeout hasn't expired yet. Find out next
		 * expiration date to be handled after this run.
		 */
		if (ktime_after(expires, now)) {
			next = ktime_before(expires, next) ? expires : next;
			continue;
		}

		// avoid further transitions if locked
		if (test_bit(SSH_PACKET_SF_LOCKED_BIT, &p->state))
			continue;

		trace_ssam_packet_timeout(p);

		// check if we still have some tries left
		try = ssh_packet_priority_get_try(READ_ONCE(p->priority));
		if (likely(try < SSH_PTL_MAX_PACKET_TRIES)) {
			resub = true;
			__ssh_ptl_resubmit(p);
			continue;
		}

		// no more tries left: cancel the packet

		// if someone else has locked the packet already, don't use it
		if (test_and_set_bit(SSH_PACKET_SF_LOCKED_BIT, &p->state))
			continue;

		/*
		 * We have now marked the packet as locked. Thus it cannot be
		 * added to the pending list again after we've removed it here.
		 * We can therefore re-use the pending_node of this packet
		 * temporarily.
		 */

		clear_bit(SSH_PACKET_SF_PENDING_BIT, &p->state);

		atomic_dec(&ptl->pending.count);
		list_del(&p->pending_node);

		list_add_tail(&p->pending_node, &claimed);
	}

	spin_unlock(&ptl->pending.lock);

	// cancel and complete the packet
	list_for_each_entry_safe(p, n, &claimed, pending_node) {
		if (!test_and_set_bit(SSH_PACKET_SF_COMPLETED_BIT, &p->state)) {
			ssh_ptl_queue_remove(p);
			__ssh_ptl_complete(p, -ETIMEDOUT);
		}

		// drop the reference we've obtained by removing it from pending
		list_del(&p->pending_node);
		ssh_packet_put(p);
	}

	// ensure that reaper doesn't run again immediately
	next = max(next, ktime_add(now, SSH_PTL_PACKET_TIMEOUT_RESOLUTION));
	if (next != KTIME_MAX)
		ssh_ptl_timeout_reaper_mod(ptl, now, next);

	// force-wakeup to properly handle re-transmits if we've re-submitted
	ssh_ptl_tx_wakeup(ptl, resub);
}


static bool ssh_ptl_rx_blacklist_check(struct ssh_ptl *ptl, u8 seq)
{
	int i;

	// check if SEQ is blacklisted
	for (i = 0; i < ARRAY_SIZE(ptl->rx.blacklist.seqs); i++) {
		if (likely(ptl->rx.blacklist.seqs[i] != seq))
			continue;

		ptl_dbg(ptl, "ptl: ignoring repeated data packet\n");
		return true;
	}

	// update blacklist
	ptl->rx.blacklist.seqs[ptl->rx.blacklist.offset] = seq;
	ptl->rx.blacklist.offset = (ptl->rx.blacklist.offset + 1)
				   % ARRAY_SIZE(ptl->rx.blacklist.seqs);

	return false;
}

static void ssh_ptl_rx_dataframe(struct ssh_ptl *ptl,
				 const struct ssh_frame *frame,
				 const struct sshp_span *payload)
{
	if (ssh_ptl_rx_blacklist_check(ptl, frame->seq))
		return;

	ptl->ops.data_received(ptl, payload);
}

static void ssh_ptl_send_ack(struct ssh_ptl *ptl, u8 seq)
{
	struct ssh_packet_args args;
	struct ssh_packet *packet;
	struct msgbuf msgb;

	args.type = 0;
	args.priority = SSH_PACKET_PRIORITY(ACK, 0);
	args.ops = &ssh_ptl_ctrl_packet_ops;

	packet = ptl_alloc_ctrl_packet(ptl, &args, GFP_KERNEL);
	if (!packet) {
		ptl_err(ptl, "ptl: failed to allocate ACK packet\n");
		return;
	}

	msgb_init(&msgb, packet->data, packet->data_length);
	msgb_push_ack(&msgb, seq);
	packet->data_length = msgb_bytes_used(&msgb);

	ssh_ptl_submit(ptl, packet);
	ssh_packet_put(packet);
}

static void ssh_ptl_send_nak(struct ssh_ptl *ptl)
{
	struct ssh_packet_args args;
	struct ssh_packet *packet;
	struct msgbuf msgb;

	args.type = 0;
	args.priority = SSH_PACKET_PRIORITY(NAK, 0);
	args.ops = &ssh_ptl_ctrl_packet_ops;

	packet = ptl_alloc_ctrl_packet(ptl, &args, GFP_KERNEL);
	if (!packet) {
		ptl_err(ptl, "ptl: failed to allocate NAK packet\n");
		return;
	}

	msgb_init(&msgb, packet->data, packet->data_length);
	msgb_push_nak(&msgb);
	packet->data_length = msgb_bytes_used(&msgb);

	ssh_ptl_submit(ptl, packet);
	ssh_packet_put(packet);
}

static size_t ssh_ptl_rx_eval(struct ssh_ptl *ptl, struct sshp_span *source)
{
	struct ssh_frame *frame;
	struct sshp_span payload;
	struct sshp_span aligned;
	bool syn_found;
	int status;

	// error injection: modify data to simulate corrupt SYN bytes
	ssh_ptl_rx_inject_invalid_syn(ptl, source);

	// find SYN
	syn_found = sshp_find_syn(source, &aligned);

	if (unlikely(aligned.ptr - source->ptr) > 0) {
		ptl_warn(ptl, "rx: parser: invalid start of frame, skipping\n");

		/*
		 * Notes:
		 * - This might send multiple NAKs in case the communication
		 *   starts with an invalid SYN and is broken down into multiple
		 *   pieces. This should generally be handled fine, we just
		 *   might receive duplicate data in this case, which is
		 *   detected when handling data frames.
		 * - This path will also be executed on invalid CRCs: When an
		 *   invalid CRC is encountered, the code below will skip data
		 *   until direclty after the SYN. This causes the search for
		 *   the next SYN, which is generally not placed directly after
		 *   the last one.
		 */
		ssh_ptl_send_nak(ptl);
	}

	if (unlikely(!syn_found))
		return aligned.ptr - source->ptr;

	// error injection: modify data to simulate corruption
	ssh_ptl_rx_inject_invalid_data(ptl, &aligned);

	// parse and validate frame
	status = sshp_parse_frame(&ptl->serdev->dev, &aligned, &frame, &payload,
				  SSH_PTL_RX_BUF_LEN);
	if (status)	// invalid frame: skip to next syn
		return aligned.ptr - source->ptr + sizeof(u16);
	if (!frame)	// not enough data
		return aligned.ptr - source->ptr;

	trace_ssam_rx_frame_received(frame);

	switch (frame->type) {
	case SSH_FRAME_TYPE_ACK:
		ssh_ptl_acknowledge(ptl, frame->seq);
		break;

	case SSH_FRAME_TYPE_NAK:
		ssh_ptl_resubmit_pending(ptl);
		break;

	case SSH_FRAME_TYPE_DATA_SEQ:
		ssh_ptl_send_ack(ptl, frame->seq);
		/* fallthrough */

	case SSH_FRAME_TYPE_DATA_NSQ:
		ssh_ptl_rx_dataframe(ptl, frame, &payload);
		break;

	default:
		ptl_warn(ptl, "ptl: received frame with unknown type 0x%02x\n",
			 frame->type);
		break;
	}

	return aligned.ptr - source->ptr + SSH_MESSAGE_LENGTH(frame->len);
}

static int ssh_ptl_rx_threadfn(void *data)
{
	struct ssh_ptl *ptl = data;

	while (true) {
		struct sshp_span span;
		size_t offs = 0;
		size_t n;

		wait_event_interruptible(ptl->rx.wq,
					 !kfifo_is_empty(&ptl->rx.fifo)
					 || kthread_should_stop());
		if (kthread_should_stop())
			break;

		// copy from fifo to evaluation buffer
		n = sshp_buf_read_from_fifo(&ptl->rx.buf, &ptl->rx.fifo);

		ptl_dbg(ptl, "rx: received data (size: %zu)\n", n);
		print_hex_dump_debug("rx: ", DUMP_PREFIX_OFFSET, 16, 1,
				     ptl->rx.buf.ptr + ptl->rx.buf.len - n,
				     n, false);

		// parse until we need more bytes or buffer is empty
		while (offs < ptl->rx.buf.len) {
			sshp_buf_span_from(&ptl->rx.buf, offs, &span);
			n = ssh_ptl_rx_eval(ptl, &span);
			if (n == 0)
				break;	// need more bytes

			offs += n;
		}

		// throw away the evaluated parts
		sshp_buf_drop(&ptl->rx.buf, offs);
	}

	return 0;
}

static inline void ssh_ptl_rx_wakeup(struct ssh_ptl *ptl)
{
	wake_up(&ptl->rx.wq);
}

static int ssh_ptl_rx_start(struct ssh_ptl *ptl)
{
	if (ptl->rx.thread)
		return 0;

	ptl->rx.thread = kthread_run(ssh_ptl_rx_threadfn, ptl, "surface-sh-rx");
	if (IS_ERR(ptl->rx.thread))
		return PTR_ERR(ptl->rx.thread);

	return 0;
}

static int ssh_ptl_rx_stop(struct ssh_ptl *ptl)
{
	int status = 0;

	if (ptl->rx.thread) {
		status = kthread_stop(ptl->rx.thread);
		ptl->rx.thread = NULL;
	}

	return status;
}

static int ssh_ptl_rx_rcvbuf(struct ssh_ptl *ptl, const u8 *buf, size_t n)
{
	int used;

	if (test_bit(SSH_PTL_SF_SHUTDOWN_BIT, &ptl->state))
		return used;

	used = kfifo_in(&ptl->rx.fifo, buf, n);
	if (used)
		ssh_ptl_rx_wakeup(ptl);

	return used;
}


struct ssh_flush_packet {
	struct ssh_packet base;
	struct completion completion;
	int status;
};

static void ssh_ptl_flush_complete(struct ssh_packet *p, int status)
{
	struct ssh_flush_packet *packet;

	packet = container_of(p, struct ssh_flush_packet, base);
	packet->status = status;
}

static void ssh_ptl_flush_release(struct ssh_packet *p)
{
	struct ssh_flush_packet *packet;

	packet = container_of(p, struct ssh_flush_packet, base);
	complete_all(&packet->completion);
}

static const struct ssh_packet_ops ssh_flush_packet_ops =  {
	.complete = ssh_ptl_flush_complete,
	.release = ssh_ptl_flush_release,
};

/**
 * ssh_ptl_flush - flush the packet transmission layer
 * @ptl:     packet transmission layer
 * @timeout: timeout for the flush operation in jiffies
 *
 * Queue a special flush-packet and wait for its completion. This packet will
 * be completed after all other currently queued and pending packets have been
 * completed. Flushing guarantees that all previously submitted data packets
 * have been fully completed before this call returns. Additionally, flushing
 * blocks execution of all later submitted data packets until the flush has been
 * completed.
 *
 * Control (i.e. ACK/NAK) packets that have been submitted after this call will
 * be placed before the flush packet in the queue, as long as the flush-packet
 * has not been chosen for processing yet.
 *
 * Flushing, even when no new data packets are submitted after this call, does
 * not guarantee that no more packets are scheduled. For example, incoming
 * messages can promt automated submission of ACK or NAK type packets. If this
 * happens while the flush-packet is being processed (i.e. after it has been
 * taken from the queue), such packets may still be queued after this function
 * returns.
 *
 * Return: Zero on success, -ETIMEDOUT if the flush timed out and has been
 * canceled as a result of the timeout, or -ESHUTDOWN if the packet transmission
 * layer has been shut down before this call. May also return -EINTR if the
 * packet transmission has been interrupted.
 */
static int ssh_ptl_flush(struct ssh_ptl *ptl, unsigned long timeout)
{
	struct ssh_flush_packet packet;
	struct ssh_packet_args args;
	int status;

	args.type = SSH_PACKET_TY_FLUSH | SSH_PACKET_TY_BLOCKING;
	args.priority = SSH_PACKET_PRIORITY(FLUSH, 0);
	args.ops = &ssh_flush_packet_ops;

	ssh_packet_init(&packet.base, &args);
	init_completion(&packet.completion);

	status = ssh_ptl_submit(ptl, &packet.base);
	if (status)
		return status;

	ssh_packet_put(&packet.base);

	if (wait_for_completion_timeout(&packet.completion, timeout))
		return 0;

	ssh_ptl_cancel(&packet.base);
	wait_for_completion(&packet.completion);

	WARN_ON(packet.status != 0 && packet.status != -ECANCELED
		&& packet.status != -ESHUTDOWN && packet.status != -EINTR);

	return packet.status == -ECANCELED ? -ETIMEDOUT : status;
}

/**
 * ssh_ptl_shutdown - shut down the packet transmission layer
 * @ptl:     packet transmission layer
 *
 * Shuts down the packet transmission layer, removing and canceling all queued
 * and pending packets. Packets canceled by this operation will be completed
 * with -ESHUTDOWN as status.
 *
 * As a result of this function, the transmission layer will be marked as shut
 * down. Submission of packets after the transmission layer has been shut down
 * will fail with -ESHUTDOWN.
 */
static void ssh_ptl_shutdown(struct ssh_ptl *ptl)
{
	LIST_HEAD(complete_q);
	LIST_HEAD(complete_p);
	struct ssh_packet *p, *n;
	int status;

	// ensure that no new packets (including ACK/NAK) can be submitted
	set_bit(SSH_PTL_SF_SHUTDOWN_BIT, &ptl->state);
	smp_mb__after_atomic();

	status = ssh_ptl_rx_stop(ptl);
	if (status)
		ptl_err(ptl, "ptl: failed to stop receiver thread\n");

	status = ssh_ptl_tx_stop(ptl);
	if (status)
		ptl_err(ptl, "ptl: failed to stop transmitter thread\n");

	cancel_delayed_work_sync(&ptl->rtx_timeout.reaper);

	/*
	 * At this point, all threads have been stopped. This means that the
	 * only references to packets from inside the system are in the queue
	 * and pending set.
	 *
	 * Note: We still need locks here because someone could still be
	 * cancelling packets.
	 *
	 * Note 2: We can re-use queue_node (or pending_node) if we mark the
	 * packet as locked an then remove it from the queue (or pending set
	 * respecitvely). Marking the packet as locked avoids re-queueing
	 * (which should already be prevented by having stopped the treads...)
	 * and not setting QUEUED_BIT (or PENDING_BIT) prevents removal from a
	 * new list via other threads (e.g. canellation).
	 *
	 * Note 3: There may be overlap between complete_p and complete_q.
	 * This is handled via test_and_set_bit on the "completed" flag
	 * (also handles cancelation).
	 */

	// mark queued packets as locked and move them to complete_q
	spin_lock(&ptl->queue.lock);
	list_for_each_entry_safe(p, n, &ptl->queue.head, queue_node) {
		set_bit(SSH_PACKET_SF_LOCKED_BIT, &p->state);
		smp_mb__before_atomic();
		clear_bit(SSH_PACKET_SF_QUEUED_BIT, &p->state);

		list_del(&p->queue_node);
		list_add_tail(&p->queue_node, &complete_q);
	}
	spin_unlock(&ptl->queue.lock);

	// mark pending packets as locked and move them to complete_p
	spin_lock(&ptl->pending.lock);
	list_for_each_entry_safe(p, n, &ptl->pending.head, pending_node) {
		set_bit(SSH_PACKET_SF_LOCKED_BIT, &p->state);
		smp_mb__before_atomic();
		clear_bit(SSH_PACKET_SF_PENDING_BIT, &p->state);

		list_del(&p->pending_node);
		list_add_tail(&p->pending_node, &complete_q);
	}
	atomic_set(&ptl->pending.count, 0);
	spin_unlock(&ptl->pending.lock);

	// complete and drop packets on complete_q
	list_for_each_entry(p, &complete_q, queue_node) {
		if (!test_and_set_bit(SSH_PACKET_SF_COMPLETED_BIT, &p->state))
			__ssh_ptl_complete(p, -ESHUTDOWN);

		ssh_packet_put(p);
	}

	// complete and drop packets on complete_p
	list_for_each_entry(p, &complete_p, pending_node) {
		if (!test_and_set_bit(SSH_PACKET_SF_COMPLETED_BIT, &p->state))
			__ssh_ptl_complete(p, -ESHUTDOWN);

		ssh_packet_put(p);
	}

	/*
	 * At this point we have guaranteed that the system doesn't reference
	 * any packets any more.
	 */
}

static inline struct device *ssh_ptl_get_device(struct ssh_ptl *ptl)
{
	return &ptl->serdev->dev;
}

static int ssh_ptl_init(struct ssh_ptl *ptl, struct serdev_device *serdev,
			struct ssh_ptl_ops *ops)
{
	int i, status;

	ptl->serdev = serdev;
	ptl->state = 0;

	spin_lock_init(&ptl->queue.lock);
	INIT_LIST_HEAD(&ptl->queue.head);

	spin_lock_init(&ptl->pending.lock);
	INIT_LIST_HEAD(&ptl->pending.head);
	atomic_set_release(&ptl->pending.count, 0);

	ptl->tx.thread = NULL;
	ptl->tx.thread_signal = false;
	ptl->tx.packet = NULL;
	ptl->tx.offset = 0;
	init_waitqueue_head(&ptl->tx.thread_wq);
	init_waitqueue_head(&ptl->tx.packet_wq);

	ptl->rx.thread = NULL;
	init_waitqueue_head(&ptl->rx.wq);

	ptl->rtx_timeout.timeout = SSH_PTL_PACKET_TIMEOUT;
	ptl->rtx_timeout.expires = KTIME_MAX;
	INIT_DELAYED_WORK(&ptl->rtx_timeout.reaper, ssh_ptl_timeout_reap);

	ptl->ops = *ops;

	// initialize SEQ blacklist with invalid sequence IDs
	for (i = 0; i < ARRAY_SIZE(ptl->rx.blacklist.seqs); i++)
		ptl->rx.blacklist.seqs[i] = 0xFFFF;
	ptl->rx.blacklist.offset = 0;

	status = kfifo_alloc(&ptl->rx.fifo, SSH_PTL_RX_FIFO_LEN, GFP_KERNEL);
	if (status)
		return status;

	status = sshp_buf_alloc(&ptl->rx.buf, SSH_PTL_RX_BUF_LEN, GFP_KERNEL);
	if (status)
		kfifo_free(&ptl->rx.fifo);

	return status;
}

static void ssh_ptl_destroy(struct ssh_ptl *ptl)
{
	kfifo_free(&ptl->rx.fifo);
	sshp_buf_free(&ptl->rx.buf);
}


/* -- Request transport layer (rtl). ---------------------------------------- */

#define SSH_RTL_REQUEST_TIMEOUT			ms_to_ktime(1000)
#define SSH_RTL_REQUEST_TIMEOUT_RESOLUTION	ms_to_ktime(max(2000 / HZ, 50))

#define SSH_RTL_MAX_PENDING		3


enum ssh_rtl_state_flags {
	SSH_RTL_SF_SHUTDOWN_BIT,
};

struct ssh_rtl_ops {
	void (*handle_event)(struct ssh_rtl *rtl, const struct ssh_command *cmd,
			     const struct sshp_span *data);
};

struct ssh_rtl {
	struct ssh_ptl ptl;
	unsigned long state;

	struct {
		spinlock_t lock;
		struct list_head head;
	} queue;

	struct {
		spinlock_t lock;
		struct list_head head;
		atomic_t count;
	} pending;

	struct {
		struct work_struct work;
	} tx;

	struct {
		ktime_t timeout;
		ktime_t expires;
		struct delayed_work reaper;
	} rtx_timeout;

	struct ssh_rtl_ops ops;
};


#define rtl_dbg(r, fmt, ...)  ptl_dbg(&(r)->ptl, fmt, ##__VA_ARGS__)
#define rtl_info(p, fmt, ...) ptl_info(&(p)->ptl, fmt, ##__VA_ARGS__)
#define rtl_warn(r, fmt, ...) ptl_warn(&(r)->ptl, fmt, ##__VA_ARGS__)
#define rtl_err(r, fmt, ...)  ptl_err(&(r)->ptl, fmt, ##__VA_ARGS__)
#define rtl_dbg_cond(r, fmt, ...) __ssam_prcond(rtl_dbg, r, fmt, ##__VA_ARGS__)

#define to_ssh_rtl(ptr, member) \
	container_of(ptr, struct ssh_rtl, member)

#define to_ssh_request(ptr, member) \
	container_of(ptr, struct ssh_request, member)


/**
 * ssh_rtl_should_drop_response - error injection hook to drop request responses
 *
 * Useful to cause request transmission timeouts in the driver by dropping the
 * response to a request.
 */
static noinline_if_inject bool ssh_rtl_should_drop_response(void)
{
	return false;
}
ALLOW_ERROR_INJECTION(ssh_rtl_should_drop_response, TRUE);


static inline void ssh_request_get(struct ssh_request *rqst)
{
	ssh_packet_get(&rqst->packet);
}

static inline void ssh_request_put(struct ssh_request *rqst)
{
	ssh_packet_put(&rqst->packet);
}


static inline u16 ssh_request_get_rqid(struct ssh_request *rqst)
{
	return get_unaligned_le16(rqst->packet.data
				  + SSH_MSGOFFSET_COMMAND(rqid));
}

static inline u32 ssh_request_get_rqid_safe(struct ssh_request *rqst)
{
	if (!rqst->packet.data)
		return -1;

	return ssh_request_get_rqid(rqst);
}


static void ssh_rtl_queue_remove(struct ssh_request *rqst)
{
	bool remove;

	spin_lock(&rqst->rtl->queue.lock);

	remove = test_and_clear_bit(SSH_REQUEST_SF_QUEUED_BIT, &rqst->state);
	if (remove)
		list_del(&rqst->node);

	spin_unlock(&rqst->rtl->queue.lock);

	if (remove)
		ssh_request_put(rqst);
}

static void ssh_rtl_pending_remove(struct ssh_request *rqst)
{
	bool remove;

	spin_lock(&rqst->rtl->pending.lock);

	remove = test_and_clear_bit(SSH_REQUEST_SF_PENDING_BIT, &rqst->state);
	if (remove) {
		atomic_dec(&rqst->rtl->pending.count);
		list_del(&rqst->node);
	}

	spin_unlock(&rqst->rtl->pending.lock);

	if (remove)
		ssh_request_put(rqst);
}


static void ssh_rtl_complete_with_status(struct ssh_request *rqst, int status)
{
	struct ssh_rtl *rtl = READ_ONCE(rqst->rtl);

	trace_ssam_request_complete(rqst, status);

	// rqst->rtl may not be set if we're cancelling before submitting
	rtl_dbg_cond(rtl, "rtl: completing request (rqid: 0x%04x,"
		     " status: %d)\n", ssh_request_get_rqid_safe(rqst), status);

	rqst->ops->complete(rqst, NULL, NULL, status);
}

static void ssh_rtl_complete_with_rsp(struct ssh_request *rqst,
				      const struct ssh_command *cmd,
				      const struct sshp_span *data)
{
	trace_ssam_request_complete(rqst, 0);

	rtl_dbg(rqst->rtl, "rtl: completing request with response"
		" (rqid: 0x%04x)\n", ssh_request_get_rqid(rqst));

	rqst->ops->complete(rqst, cmd, data, 0);
}


static bool ssh_rtl_tx_can_process(struct ssh_request *rqst)
{
	if (test_bit(SSH_REQUEST_TY_FLUSH_BIT, &rqst->state))
		return !atomic_read(&rqst->rtl->pending.count);

	return atomic_read(&rqst->rtl->pending.count) < SSH_RTL_MAX_PENDING;
}

static struct ssh_request *ssh_rtl_tx_next(struct ssh_rtl *rtl)
{
	struct ssh_request *rqst = ERR_PTR(-ENOENT);
	struct ssh_request *p, *n;

	spin_lock(&rtl->queue.lock);

	// find first non-locked request and remove it
	list_for_each_entry_safe(p, n, &rtl->queue.head, node) {
		if (unlikely(test_bit(SSH_REQUEST_SF_LOCKED_BIT, &p->state)))
			continue;

		if (!ssh_rtl_tx_can_process(p)) {
			rqst = ERR_PTR(-EBUSY);
			break;
		}

		/*
		 * Remove from queue and mark as transmitting. Ensure that the
		 * state does not get zero via memory barrier.
		 */
		set_bit(SSH_REQUEST_SF_TRANSMITTING_BIT, &p->state);
		smp_mb__before_atomic();
		clear_bit(SSH_REQUEST_SF_QUEUED_BIT, &p->state);

		list_del(&p->node);

		rqst = p;
		break;
	}

	spin_unlock(&rtl->queue.lock);
	return rqst;
}

static int ssh_rtl_tx_pending_push(struct ssh_request *rqst)
{
	struct ssh_rtl *rtl = rqst->rtl;

	spin_lock(&rtl->pending.lock);

	if (test_bit(SSH_REQUEST_SF_LOCKED_BIT, &rqst->state)) {
		spin_unlock(&rtl->pending.lock);
		return -EINVAL;
	}

	if (test_and_set_bit(SSH_REQUEST_SF_PENDING_BIT, &rqst->state)) {
		spin_unlock(&rtl->pending.lock);
		return -EALREADY;
	}

	atomic_inc(&rtl->pending.count);
	ssh_request_get(rqst);
	list_add_tail(&rqst->node, &rtl->pending.head);

	spin_unlock(&rtl->pending.lock);
	return 0;
}

static int ssh_rtl_tx_try_process_one(struct ssh_rtl *rtl)
{
	struct ssh_request *rqst;
	int status;

	// get and prepare next request for transmit
	rqst = ssh_rtl_tx_next(rtl);
	if (IS_ERR(rqst))
		return PTR_ERR(rqst);

	// add to/mark as pending
	status = ssh_rtl_tx_pending_push(rqst);
	if (status) {
		ssh_request_put(rqst);
		return -EAGAIN;
	}

	// submit packet
	status = ssh_ptl_submit(&rtl->ptl, &rqst->packet);
	if (status == -ESHUTDOWN) {
		/*
		 * Packet has been refused due to the packet layer shutting
		 * down. Complete it here.
		 */
		set_bit(SSH_REQUEST_SF_LOCKED_BIT, &rqst->state);
		smp_mb__after_atomic();

		ssh_rtl_pending_remove(rqst);
		ssh_rtl_complete_with_status(rqst, -ESHUTDOWN);

		ssh_request_put(rqst);
		return -ESHUTDOWN;

	} else if (status) {
		/*
		 * If submitting the packet failed and the packet layer isn't
		 * shutting down, the packet has either been submmitted/queued
		 * before (-EALREADY, which cannot happen as we have guaranteed
		 * that requests cannot be re-submitted), or the packet was
		 * marked as locked (-EINVAL). To mark the packet locked at this
		 * stage, the request, and thus the packets itself, had to have
		 * been canceled. Simply drop the reference. Cancellation itself
		 * will remove it from the set of pending requests.
		 */

		WARN_ON(status != -EINVAL);

		ssh_request_put(rqst);
		return -EAGAIN;
	}

	ssh_request_put(rqst);
	return 0;
}

static bool ssh_rtl_queue_empty(struct ssh_rtl *rtl)
{
	bool empty;

	spin_lock(&rtl->queue.lock);
	empty = list_empty(&rtl->queue.head);
	spin_unlock(&rtl->queue.lock);

	return empty;
}

static bool ssh_rtl_tx_schedule(struct ssh_rtl *rtl)
{
	if (atomic_read(&rtl->pending.count) >= SSH_RTL_MAX_PENDING)
		return false;

	if (ssh_rtl_queue_empty(rtl))
		return false;

	return schedule_work(&rtl->tx.work);
}

static void ssh_rtl_tx_work_fn(struct work_struct *work)
{
	struct ssh_rtl *rtl = to_ssh_rtl(work, tx.work);
	int i, status;

	/*
	 * Try to be nice and not block the workqueue: Run a maximum of 10
	 * tries, then re-submit if necessary. This should not be neccesary,
	 * for normal execution, but guarantee it anyway.
	 */
	for (i = 0; i < 10; i++) {
		status = ssh_rtl_tx_try_process_one(rtl);
		if (status == -ENOENT || status == -EBUSY)
			return;		// no more requests to process

		if (status == -ESHUTDOWN) {
			/*
			 * Packet system shutting down. No new packets can be
			 * transmitted. Return silently, the party initiating
			 * the shutdown should handle the rest.
			 */
			return;
		}

		WARN_ON(status != 0 && status != -EAGAIN);
	}

	// out of tries, reschedule
	ssh_rtl_tx_schedule(rtl);
}


static int ssh_rtl_submit(struct ssh_rtl *rtl, struct ssh_request *rqst)
{
	trace_ssam_request_submit(rqst);

	/*
	 * Ensure that requests expecting a response are sequenced. If this
	 * invariant ever changes, see the comment in ssh_rtl_complete on what
	 * is required to be changed in the code.
	 */
	if (test_bit(SSH_REQUEST_TY_HAS_RESPONSE_BIT, &rqst->state))
		if (!(rqst->packet.type & SSH_PACKET_TY_SEQUENCED))
			return -EINVAL;

	// try to set rtl and check if this request has already been submitted
	if (cmpxchg(&rqst->rtl, NULL, rtl) != NULL)
		return -EALREADY;

	spin_lock(&rtl->queue.lock);

	if (test_bit(SSH_RTL_SF_SHUTDOWN_BIT, &rtl->state)) {
		spin_unlock(&rtl->queue.lock);
		return -ESHUTDOWN;
	}

	if (test_bit(SSH_REQUEST_SF_LOCKED_BIT, &rqst->state)) {
		spin_unlock(&rtl->queue.lock);
		return -EINVAL;
	}

	ssh_request_get(rqst);
	set_bit(SSH_REQUEST_SF_QUEUED_BIT, &rqst->state);
	list_add_tail(&rqst->node, &rtl->queue.head);

	spin_unlock(&rtl->queue.lock);

	ssh_rtl_tx_schedule(rtl);
	return 0;
}


static void ssh_rtl_timeout_reaper_mod(struct ssh_rtl *rtl, ktime_t now,
				       ktime_t expires)
{
	unsigned long delta = msecs_to_jiffies(ktime_ms_delta(expires, now));
	ktime_t aexp = ktime_add(expires, SSH_RTL_REQUEST_TIMEOUT_RESOLUTION);
	ktime_t old;

	// re-adjust / schedule reaper if it is above resolution delta
	old = READ_ONCE(rtl->rtx_timeout.expires);
	while (ktime_before(aexp, old))
		old = cmpxchg64(&rtl->rtx_timeout.expires, old, expires);

	// if we updated the reaper expiration, modify work timeout
	if (old == expires)
		mod_delayed_work(system_wq, &rtl->rtx_timeout.reaper, delta);
}

static void ssh_rtl_timeout_start(struct ssh_request *rqst)
{
	struct ssh_rtl *rtl = rqst->rtl;
	ktime_t timestamp = ktime_get_coarse_boottime();
	ktime_t timeout = rtl->rtx_timeout.timeout;

	if (test_bit(SSH_REQUEST_SF_LOCKED_BIT, &rqst->state))
		return;

	WRITE_ONCE(rqst->timestamp, timestamp);
	smp_mb__after_atomic();

	ssh_rtl_timeout_reaper_mod(rqst->rtl, timestamp, timestamp + timeout);
}


static void ssh_rtl_complete(struct ssh_rtl *rtl,
			     const struct ssh_command *command,
			     const struct sshp_span *command_data)
{
	struct ssh_request *r = NULL;
	struct ssh_request *p, *n;
	u16 rqid = get_unaligned_le16(&command->rqid);

	trace_ssam_rx_response_received(command, command_data->len);

	/*
	 * Get request from pending based on request ID and mark it as response
	 * received and locked.
	 */
	spin_lock(&rtl->pending.lock);
	list_for_each_entry_safe(p, n, &rtl->pending.head, node) {
		// we generally expect requests to be processed in order
		if (unlikely(ssh_request_get_rqid(p) != rqid))
			continue;

		// simulate response timeout
		if (ssh_rtl_should_drop_response()) {
			spin_unlock(&rtl->pending.lock);

			trace_ssam_ei_rx_drop_response(p);
			rtl_info(rtl, "request error injection: "
				 "dropping response for request %p\n",
				 &p->packet);
			return;
		}

		/*
		 * Mark as "response received" and "locked" as we're going to
		 * complete it. Ensure that the state doesn't get zero by
		 * employing a memory barrier.
		 */
		set_bit(SSH_REQUEST_SF_LOCKED_BIT, &p->state);
		set_bit(SSH_REQUEST_SF_RSPRCVD_BIT, &p->state);
		smp_mb__before_atomic();
		clear_bit(SSH_REQUEST_SF_PENDING_BIT, &p->state);

		atomic_dec(&rtl->pending.count);
		list_del(&p->node);

		r = p;
		break;
	}
	spin_unlock(&rtl->pending.lock);

	if (!r) {
		rtl_warn(rtl, "rtl: dropping unexpected command message"
			 " (rqid = 0x%04x)\n", rqid);
		return;
	}

	// if the request hasn't been completed yet, we will do this now
	if (test_and_set_bit(SSH_REQUEST_SF_COMPLETED_BIT, &r->state)) {
		ssh_request_put(r);
		ssh_rtl_tx_schedule(rtl);
		return;
	}

	/*
	 * Make sure the request has been transmitted. In case of a sequenced
	 * request, we are guaranteed that the completion callback will run on
	 * the receiver thread directly when the ACK for the packet has been
	 * received. Similarly, this function is guaranteed to run on the
	 * receiver thread. Thus we are guaranteed that if the packet has been
	 * successfully transmitted and received an ACK, the transmitted flag
	 * has been set and is visible here.
	 *
	 * We are currently not handling unsequenced packets here, as those
	 * should never expect a response as ensured in ssh_rtl_submit. If this
	 * ever changes, one would have to test for
	 *
	 * 	(r->state & (transmitting | transmitted))
	 *
	 * on unsequenced packets to determine if they could have been
	 * transmitted. There are no synchronization guarantees as in the
	 * sequenced case, since, in this case, the callback function will not
	 * run on the same thread. Thus an exact determination is impossible.
	 */
	if (!test_bit(SSH_REQUEST_SF_TRANSMITTED_BIT, &r->state)) {
		rtl_err(rtl, "rtl: received response before ACK for request"
			" (rqid = 0x%04x)\n", rqid);

		/*
		 * NB: Timeout has already been canceled, request already been
		 * removed from pending and marked as locked and completed. As
		 * we receive a "false" response, the packet might still be
		 * queued though.
		 */
		ssh_rtl_queue_remove(r);

		ssh_rtl_complete_with_status(r, -EREMOTEIO);
		ssh_request_put(r);

		ssh_rtl_tx_schedule(rtl);
		return;
	}

	/*
	 * NB: Timeout has already been canceled, request already been
	 * removed from pending and marked as locked and completed. The request
	 * can also not be queued any more, as it has been marked as
	 * transmitting and later transmitted. Thus no need to remove it from
	 * anywhere.
	 */

	ssh_rtl_complete_with_rsp(r, command, command_data);
	ssh_request_put(r);

	ssh_rtl_tx_schedule(rtl);
}


static bool ssh_rtl_cancel_nonpending(struct ssh_request *r)
{
	unsigned long state, fixed;
	bool remove;

	/*
	 * Handle unsubmitted request: Try to mark the packet as locked,
	 * expecting the state to be zero (i.e. unsubmitted). Note that, if
	 * setting the state worked, we might still be adding the packet to the
	 * queue in a currently executing submit call. In that case, however,
	 * rqst->rtl must have been set previously, as locked is checked after
	 * setting rqst->rtl. Thus only if we successfully lock this request and
	 * rqst->rtl is NULL, we have successfully removed the request.
	 * Otherwise we need to try and grab it from the queue.
	 *
	 * Note that if the CMPXCHG fails, we are guaranteed that rqst->rtl has
	 * been set and is non-NULL, as states can only be nonzero after this
	 * has been set. Also note that we need to fetch the static (type) flags
         * to ensure that they don't cause the cmpxchg to fail.
	 */
        fixed = READ_ONCE(r->state) & SSH_REQUEST_FLAGS_TY_MASK;
	state = cmpxchg(&r->state, fixed, SSH_REQUEST_SF_LOCKED_BIT);
	if (!state && !READ_ONCE(r->rtl)) {
		if (test_and_set_bit(SSH_REQUEST_SF_COMPLETED_BIT, &r->state))
			return true;

		ssh_rtl_complete_with_status(r, -ECANCELED);
		return true;
	}

	spin_lock(&r->rtl->queue.lock);

	/*
	 * Note: 1) Requests cannot be re-submitted. 2) If a request is queued,
	 * it cannot be "transmitting"/"pending" yet. Thus, if we successfully
	 * remove the the request here, we have removed all its occurences in
	 * the system.
	 */

	remove = test_and_clear_bit(SSH_REQUEST_SF_QUEUED_BIT, &r->state);
	if (!remove) {
		spin_unlock(&r->rtl->queue.lock);
		return false;
	}

	set_bit(SSH_REQUEST_SF_LOCKED_BIT, &r->state);
	list_del(&r->node);

	spin_unlock(&r->rtl->queue.lock);

	ssh_request_put(r);	// drop reference obtained from queue

	if (test_and_set_bit(SSH_REQUEST_SF_COMPLETED_BIT, &r->state))
		return true;

	ssh_rtl_complete_with_status(r, -ECANCELED);
	return true;
}

static bool ssh_rtl_cancel_pending(struct ssh_request *r)
{
	// if the packet is already locked, it's going to be removed shortly
	if (test_and_set_bit(SSH_REQUEST_SF_LOCKED_BIT, &r->state))
		return true;

	/*
	 * Now that we have locked the packet, we have guaranteed that it can't
	 * be added to the system any more. If rqst->rtl is zero, the locked
	 * check in ssh_rtl_submit has not been run and any submission,
	 * currently in progress or called later, won't add the packet. Thus we
	 * can directly complete it.
	 */
	if (!READ_ONCE(r->rtl)) {
		if (test_and_set_bit(SSH_REQUEST_SF_COMPLETED_BIT, &r->state))
			return true;

		ssh_rtl_complete_with_status(r, -ECANCELED);
		return true;
	}

	/*
	 * Try to cancel the packet. If the packet has not been completed yet,
	 * this will subsequently (and synchronously) call the completion
	 * callback of the packet, which will complete the request.
	 */
	ssh_ptl_cancel(&r->packet);

	/*
	 * If the packet has been completed with success, i.e. has not been
	 * canceled by the above call, the request may not have been completed
	 * yet (may be waiting for a response). Check if we need to do this
	 * here.
	 */
	if (test_and_set_bit(SSH_REQUEST_SF_COMPLETED_BIT, &r->state))
		return true;

	ssh_rtl_queue_remove(r);
	ssh_rtl_pending_remove(r);
	ssh_rtl_complete_with_status(r, -ECANCELED);

	return true;
}

static bool ssh_rtl_cancel(struct ssh_request *rqst, bool pending)
{
	struct ssh_rtl *rtl;
	bool canceled;

	if (test_and_set_bit(SSH_REQUEST_SF_CANCELED_BIT, &rqst->state))
		return true;

	trace_ssam_request_cancel(rqst);

	if (pending)
		canceled = ssh_rtl_cancel_pending(rqst);
	else
		canceled = ssh_rtl_cancel_nonpending(rqst);

	// note: rqst->rtl may be NULL if request has not been submitted yet
	rtl = READ_ONCE(rqst->rtl);
	if (canceled && rtl)
		ssh_rtl_tx_schedule(rtl);

	return canceled;
}


static void ssh_rtl_packet_callback(struct ssh_packet *p, int status)
{
	struct ssh_request *r = to_ssh_request(p, packet);

	if (unlikely(status)) {
		set_bit(SSH_REQUEST_SF_LOCKED_BIT, &r->state);

		if (test_and_set_bit(SSH_REQUEST_SF_COMPLETED_BIT, &r->state))
			return;

		/*
		 * The packet may get cancelled even though it has not been
		 * submitted yet. The request may still be queued. Check the
		 * queue and remove it if necessary. As the timeout would have
		 * been started in this function on success, there's no need to
		 * cancel it here.
		 */
		ssh_rtl_queue_remove(r);
		ssh_rtl_pending_remove(r);
		ssh_rtl_complete_with_status(r, status);

		ssh_rtl_tx_schedule(r->rtl);
		return;
	}

	/*
	 * Mark as transmitted, ensure that state doesn't get zero by inserting
	 * a memory barrier.
	 */
	set_bit(SSH_REQUEST_SF_TRANSMITTED_BIT, &r->state);
	smp_mb__before_atomic();
	clear_bit(SSH_REQUEST_SF_TRANSMITTING_BIT, &r->state);

	// if we expect a response, we just need to start the timeout
	if (test_bit(SSH_REQUEST_TY_HAS_RESPONSE_BIT, &r->state)) {
		ssh_rtl_timeout_start(r);
		return;
	}

	/*
	 * If we don't expect a response, lock, remove, and complete the
	 * request. Note that, at this point, the request is guaranteed to have
	 * left the queue and no timeout has been started. Thus we only need to
	 * remove it from pending. If the request has already been completed (it
	 * may have been canceled) return.
	 */

	set_bit(SSH_REQUEST_SF_LOCKED_BIT, &r->state);
	if (test_and_set_bit(SSH_REQUEST_SF_COMPLETED_BIT, &r->state))
		return;

	ssh_rtl_pending_remove(r);
	ssh_rtl_complete_with_status(r, 0);

	ssh_rtl_tx_schedule(r->rtl);
}


static ktime_t ssh_request_get_expiration(struct ssh_request *r, ktime_t timeo)
{
	ktime_t timestamp = READ_ONCE(r->timestamp);

	if (timestamp != KTIME_MAX)
		return ktime_add(timestamp, timeo);
	else
		return KTIME_MAX;
}

static void ssh_rtl_timeout_reap(struct work_struct *work)
{
	struct ssh_rtl *rtl = to_ssh_rtl(work, rtx_timeout.reaper.work);
	struct ssh_request *r, *n;
	LIST_HEAD(claimed);
	ktime_t now = ktime_get_coarse_boottime();
	ktime_t timeout = rtl->rtx_timeout.timeout;
	ktime_t next = KTIME_MAX;

	trace_ssam_rtl_timeout_reap("pending", atomic_read(&rtl->pending.count));

	/*
	 * Mark reaper as "not pending". This is done before checking any
	 * requests to avoid lost-update type problems.
	 */
	WRITE_ONCE(rtl->rtx_timeout.expires, KTIME_MAX);
	smp_mb__after_atomic();

	spin_lock(&rtl->pending.lock);
	list_for_each_entry_safe(r, n, &rtl->pending.head, node) {
		ktime_t expires = ssh_request_get_expiration(r, timeout);

		/*
		 * Check if the timeout hasn't expired yet. Find out next
		 * expiration date to be handled after this run.
		 */
		if (ktime_after(expires, now)) {
			next = ktime_before(expires, next) ? expires : next;
			continue;
		}

		// avoid further transitions if locked
		if (test_and_set_bit(SSH_REQUEST_SF_LOCKED_BIT, &r->state))
			continue;

		/*
		 * We have now marked the packet as locked. Thus it cannot be
		 * added to the pending or queued lists again after we've
		 * removed it here. We can therefore re-use the node of this
		 * packet temporarily.
		 */

		clear_bit(SSH_REQUEST_SF_PENDING_BIT, &r->state);

		atomic_dec(&rtl->pending.count);
		list_del(&r->node);

		list_add_tail(&r->node, &claimed);
	}
	spin_unlock(&rtl->pending.lock);

	// cancel and complete the request
	list_for_each_entry_safe(r, n, &claimed, node) {
		trace_ssam_request_timeout(r);

		/*
		 * At this point we've removed the packet from pending. This
		 * means that we've obtained the last (only) reference of the
		 * system to it. Thus we can just complete it.
		 */
		if (!test_and_set_bit(SSH_REQUEST_SF_COMPLETED_BIT, &r->state))
			ssh_rtl_complete_with_status(r, -ETIMEDOUT);

		// drop the reference we've obtained by removing it from pending
		list_del(&r->node);
		ssh_request_put(r);
	}

	// ensure that reaper doesn't run again immediately
	next = max(next, ktime_add(now, SSH_RTL_REQUEST_TIMEOUT_RESOLUTION));
	if (next != KTIME_MAX)
		ssh_rtl_timeout_reaper_mod(rtl, now, next);

	ssh_rtl_tx_schedule(rtl);
}


static void ssh_rtl_rx_event(struct ssh_rtl *rtl, const struct ssh_command *cmd,
			     const struct sshp_span *data)
{
	trace_ssam_rx_event_received(cmd, data->len);

	rtl_dbg(rtl, "rtl: handling event (rqid: 0x%04x)\n",
		get_unaligned_le16(&cmd->rqid));

	rtl->ops.handle_event(rtl, cmd, data);
}

static void ssh_rtl_rx_command(struct ssh_ptl *p, const struct sshp_span *data)
{
	struct ssh_rtl *rtl = to_ssh_rtl(p, ptl);
	struct device *dev = &p->serdev->dev;
	struct ssh_command *command;
	struct sshp_span command_data;

	if (sshp_parse_command(dev, data, &command, &command_data))
		return;

	if (ssh_rqid_is_event(get_unaligned_le16(&command->rqid)))
		ssh_rtl_rx_event(rtl, command, &command_data);
	else
		ssh_rtl_complete(rtl, command, &command_data);
}

static void ssh_rtl_rx_data(struct ssh_ptl *p, const struct sshp_span *data)
{
	switch (data->ptr[0]) {
	case SSH_PLD_TYPE_CMD:
		ssh_rtl_rx_command(p, data);
		break;

	default:
		ptl_err(p, "rtl: rx: unknown frame payload type"
			" (type: 0x%02x)\n", data->ptr[0]);
		break;
	}
}


static inline struct device *ssh_rtl_get_device(struct ssh_rtl *rtl)
{
	return ssh_ptl_get_device(&rtl->ptl);
}

static inline bool ssh_rtl_tx_flush(struct ssh_rtl *rtl)
{
	return flush_work(&rtl->tx.work);
}

static inline int ssh_rtl_tx_start(struct ssh_rtl *rtl)
{
	int status;
	bool sched;

	status = ssh_ptl_tx_start(&rtl->ptl);
	if (status)
		return status;

	/*
	 * If the packet layer has been shut down and restarted without shutting
	 * down the request layer, there may still be requests queued and not
	 * handled.
	 */
	spin_lock(&rtl->queue.lock);
	sched = !list_empty(&rtl->queue.head);
	spin_unlock(&rtl->queue.lock);

	if (sched)
		ssh_rtl_tx_schedule(rtl);

	return 0;
}

static inline int ssh_rtl_rx_start(struct ssh_rtl *rtl)
{
	return ssh_ptl_rx_start(&rtl->ptl);
}

static int ssh_rtl_init(struct ssh_rtl *rtl, struct serdev_device *serdev,
			struct ssh_rtl_ops *ops)
{
	struct ssh_ptl_ops ptl_ops;
	int status;

	ptl_ops.data_received = ssh_rtl_rx_data;

	status = ssh_ptl_init(&rtl->ptl, serdev, &ptl_ops);
	if (status)
		return status;

	spin_lock_init(&rtl->queue.lock);
	INIT_LIST_HEAD(&rtl->queue.head);

	spin_lock_init(&rtl->pending.lock);
	INIT_LIST_HEAD(&rtl->pending.head);
	atomic_set_release(&rtl->pending.count, 0);

	INIT_WORK(&rtl->tx.work, ssh_rtl_tx_work_fn);

	rtl->rtx_timeout.timeout = SSH_RTL_REQUEST_TIMEOUT;
	rtl->rtx_timeout.expires = KTIME_MAX;
	INIT_DELAYED_WORK(&rtl->rtx_timeout.reaper, ssh_rtl_timeout_reap);

	rtl->ops = *ops;

	return 0;
}

static void ssh_rtl_destroy(struct ssh_rtl *rtl)
{
	ssh_ptl_destroy(&rtl->ptl);
}


static void ssh_rtl_packet_release(struct ssh_packet *p)
{
	struct ssh_request *rqst = to_ssh_request(p, packet);
	rqst->ops->release(rqst);
}

static const struct ssh_packet_ops ssh_rtl_packet_ops = {
	.complete = ssh_rtl_packet_callback,
	.release = ssh_rtl_packet_release,
};

static void ssh_request_init(struct ssh_request *rqst,
			     enum ssam_request_flags flags,
			     const struct ssh_request_ops *ops)
{
	struct ssh_packet_args packet_args;

	packet_args.type = SSH_PACKET_TY_BLOCKING;
	if (!(flags & SSAM_REQUEST_UNSEQUENCED))
		packet_args.type = SSH_PACKET_TY_SEQUENCED;

	packet_args.priority = SSH_PACKET_PRIORITY(DATA, 0);
	packet_args.ops = &ssh_rtl_packet_ops;

	ssh_packet_init(&rqst->packet, &packet_args);

	rqst->rtl = NULL;
	INIT_LIST_HEAD(&rqst->node);

	rqst->state = 0;
	if (flags & SSAM_REQUEST_HAS_RESPONSE)
		rqst->state |= BIT(SSH_REQUEST_TY_HAS_RESPONSE_BIT);

	rqst->timestamp = KTIME_MAX;
	rqst->ops = ops;
}


struct ssh_flush_request {
	struct ssh_request base;
	struct completion completion;
	int status;
};

static void ssh_rtl_flush_request_complete(struct ssh_request *r,
					   const struct ssh_command *cmd,
					   const struct sshp_span *data,
					   int status)
{
	struct ssh_flush_request *rqst;

	rqst = container_of(r, struct ssh_flush_request, base);
	rqst->status = status;
}

static void ssh_rtl_flush_request_release(struct ssh_request *r)
{
	struct ssh_flush_request *rqst;

	rqst = container_of(r, struct ssh_flush_request, base);
	complete_all(&rqst->completion);
}

static const struct ssh_request_ops ssh_rtl_flush_request_ops = {
	.complete = ssh_rtl_flush_request_complete,
	.release = ssh_rtl_flush_request_release,
};

/**
 * ssh_rtl_flush - flush the request transmission layer
 * @rtl:     request transmission layer
 * @timeout: timeout for the flush operation in jiffies
 *
 * Queue a special flush request and wait for its completion. This request
 * will be completed after all other currently queued and pending requests
 * have been completed. Instead of a normal data packet, this request submits
 * a special flush packet, meaning that upon completion, also the underlying
 * packet transmission layer has been flushed.
 *
 * Flushing the request layer gurarantees that all previously submitted
 * requests have been fully completed before this call returns. Additinally,
 * flushing blocks execution of all later submitted requests until the flush
 * has been completed.
 *
 * If the caller ensures that no new requests are submitted after a call to
 * this function, the request transmission layer is guaranteed to have no
 * remaining requests when this call returns. The same guarantee does not hold
 * for the packet layer, on which control packets may still be queued after
 * this call. See the documentation of ssh_ptl_flush for more details on
 * packet layer flushing.
 *
 * Return: Zero on success, -ETIMEDOUT if the flush timed out and has been
 * canceled as a result of the timeout, or -ESHUTDOWN if the packet and/or
 * request transmission layer has been shut down before this call. May also
 * return -EINTR if the underlying packet transmission has been interrupted.
 */
static int ssh_rtl_flush(struct ssh_rtl *rtl, unsigned long timeout)
{
	const unsigned init_flags = SSAM_REQUEST_UNSEQUENCED;
	struct ssh_flush_request rqst;
	int status;

	ssh_request_init(&rqst.base, init_flags, &ssh_rtl_flush_request_ops);
	rqst.base.packet.type |= SSH_PACKET_TY_FLUSH;
	rqst.base.packet.priority = SSH_PACKET_PRIORITY(FLUSH, 0);
	rqst.base.state |= BIT(SSH_REQUEST_TY_FLUSH_BIT);

	init_completion(&rqst.completion);

	status = ssh_rtl_submit(rtl, &rqst.base);
	if (status)
		return status;

	ssh_request_put(&rqst.base);

	if (wait_for_completion_timeout(&rqst.completion, timeout))
		return 0;

	ssh_rtl_cancel(&rqst.base, true);
	wait_for_completion(&rqst.completion);

	WARN_ON(rqst.status != 0 && rqst.status != -ECANCELED
		&& rqst.status != -ESHUTDOWN && rqst.status != -EINTR);

	return rqst.status == -ECANCELED ? -ETIMEDOUT : status;
}


static void ssh_rtl_shutdown(struct ssh_rtl *rtl)
{
	struct ssh_request *r, *n;
	LIST_HEAD(claimed);
	int pending;

	set_bit(SSH_RTL_SF_SHUTDOWN_BIT, &rtl->state);
	smp_mb__after_atomic();

	// remove requests from queue
	spin_lock(&rtl->queue.lock);
	list_for_each_entry_safe(r, n, &rtl->queue.head, node) {
		set_bit(SSH_REQUEST_SF_LOCKED_BIT, &r->state);
		smp_mb__before_atomic();
		clear_bit(SSH_REQUEST_SF_QUEUED_BIT, &r->state);

		list_del(&r->node);
		list_add_tail(&r->node, &claimed);
	}
	spin_unlock(&rtl->queue.lock);

	/*
	 * We have now guaranteed that the queue is empty and no more new
	 * requests can be submitted (i.e. it will stay empty). This means that
	 * calling ssh_rtl_tx_schedule will not schedule tx.work any more. So we
	 * can simply call cancel_work_sync on tx.work here and when that
	 * returns, we've locked it down. This also means that after this call,
	 * we don't submit any more packets to the underlying packet layer, so
	 * we can also shut that down.
	 */

	cancel_work_sync(&rtl->tx.work);
	ssh_ptl_shutdown(&rtl->ptl);
	cancel_delayed_work_sync(&rtl->rtx_timeout.reaper);

	/*
	 * Shutting down the packet layer should also have caneled all requests.
	 * Thus the pending set should be empty. Attempt to handle this
	 * gracefully anyways, even though this should be dead code.
	 */

	pending = atomic_read(&rtl->pending.count);
	WARN_ON(pending);

	if (pending) {
		spin_lock(&rtl->pending.lock);
		list_for_each_entry_safe(r, n, &rtl->pending.head, node) {
			set_bit(SSH_REQUEST_SF_LOCKED_BIT, &r->state);
			smp_mb__before_atomic();
			clear_bit(SSH_REQUEST_SF_PENDING_BIT, &r->state);

			list_del(&r->node);
			list_add_tail(&r->node, &claimed);
		}
		spin_unlock(&rtl->pending.lock);
	}

	// finally cancel and complete requests
	list_for_each_entry_safe(r, n, &claimed, node) {
		// test_and_set because we still might compete with cancellation
		if (!test_and_set_bit(SSH_REQUEST_SF_COMPLETED_BIT, &r->state))
			ssh_rtl_complete_with_status(r, -ESHUTDOWN);

		// drop the reference we've obtained by removing it from list
		list_del(&r->node);
		ssh_request_put(r);
	}
}


/* -- Event notifier/callbacks. --------------------------------------------- */
/*
 * The notifier system is based on linux/notifier.h, specifically the SRCU
 * implementation. The difference to that is, that some bits of the notifier
 * call return value can be tracked accross multiple calls. This is done so that
 * handling of events can be tracked and a warning can be issued in case an
 * event goes unhandled. The idea of that waring is that it should help discover
 * and identify new/currently unimplemented features.
 */

struct ssam_nf_head {
	struct srcu_struct srcu;
	struct ssam_notifier_block __rcu *head;
};


int ssam_nfblk_call_chain(struct ssam_nf_head *nh, struct ssam_event *event)
{
	struct ssam_notifier_block *nb, *next_nb;
	int ret = 0, idx;

	idx = srcu_read_lock(&nh->srcu);

	nb = rcu_dereference_raw(nh->head);
	while (nb) {
		next_nb = rcu_dereference_raw(nb->next);

		ret = (ret & SSAM_NOTIF_STATE_MASK) | nb->fn(nb, event);
		if (ret & SSAM_NOTIF_STOP)
			break;

		nb = next_nb;
	}

	srcu_read_unlock(&nh->srcu, idx);
	return ret;
}

/*
 * Note: This function must be synchronized by the caller with respect to other
 * insert and/or remove calls.
 */
int __ssam_nfblk_insert(struct ssam_nf_head *nh, struct ssam_notifier_block *nb)
{
	struct ssam_notifier_block **link = &nh->head;

	while ((*link) != NULL) {
		if (unlikely((*link) == nb)) {
			WARN(1, "double register detected");
			return -EINVAL;
		}

		if (nb->priority > (*link)->priority)
			break;

		link = &((*link)->next);
	}

	nb->next = *link;
	rcu_assign_pointer(*link, nb);

	return 0;
}

/*
 * Note: This function must be synchronized by the caller with respect to other
 * insert and/or remove calls. On success, the caller _must_ ensure SRCU
 * synchronization by calling `synchronize_srcu(&nh->srcu)` after leaving the
 * critical section, to ensure that the removed notifier block is not in use any
 * more.
 */
int __ssam_nfblk_remove(struct ssam_nf_head *nh, struct ssam_notifier_block *nb)
{
	struct ssam_notifier_block **link = &nh->head;

	while ((*link) != NULL) {
		if ((*link) == nb) {
			rcu_assign_pointer(*link, nb->next);
			return 0;
		}

		link = &((*link)->next);
	}

	return -ENOENT;
}

static int ssam_nf_head_init(struct ssam_nf_head *nh)
{
	int status;

	status = init_srcu_struct(&nh->srcu);
	if (status)
		return status;

	nh->head = NULL;
	return 0;
}

static void ssam_nf_head_destroy(struct ssam_nf_head *nh)
{
	cleanup_srcu_struct(&nh->srcu);
}


/* -- Event/notification registry. ------------------------------------------ */

struct ssam_nf_refcount_key {
	struct ssam_event_registry reg;
	struct ssam_event_id id;
};

struct ssam_nf_refcount_entry {
	struct rb_node node;
	struct ssam_nf_refcount_key key;
	int refcount;
};

struct ssam_nf {
	struct mutex lock;
	struct rb_root refcount;
	struct ssam_nf_head head[SURFACE_SAM_SSH_NUM_EVENTS];
};


static int ssam_nf_refcount_inc(struct ssam_nf *nf,
				struct ssam_event_registry reg,
				struct ssam_event_id id)
{
	struct ssam_nf_refcount_entry *entry;
	struct ssam_nf_refcount_key key;
	struct rb_node **link = &nf->refcount.rb_node;
	struct rb_node *parent;
	int cmp;

	key.reg = reg;
	key.id = id;

	while (*link) {
		entry = rb_entry(*link, struct ssam_nf_refcount_entry, node);
		parent = *link;

		cmp = memcmp(&key, &entry->key, sizeof(key));
		if (cmp < 0) {
			link = &(*link)->rb_left;
		} else if (cmp > 0) {
			link = &(*link)->rb_right;
		} else if (entry->refcount < INT_MAX) {
			return ++entry->refcount;
		} else {
			return -ENOSPC;
		}
	}

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	entry->key = key;
	entry->refcount = 1;

	rb_link_node(&entry->node, parent, link);
	rb_insert_color(&entry->node, &nf->refcount);

	return entry->refcount;
}

static int ssam_nf_refcount_dec(struct ssam_nf *nf,
				struct ssam_event_registry reg,
				struct ssam_event_id id)
{
	struct ssam_nf_refcount_entry *entry;
	struct ssam_nf_refcount_key key;
	struct rb_node *node = nf->refcount.rb_node;
	int cmp, rc;

	key.reg = reg;
	key.id = id;

	while (node) {
		entry = rb_entry(node, struct ssam_nf_refcount_entry, node);

		cmp = memcmp(&key, &entry->key, sizeof(key));
		if (cmp < 0) {
			node = node->rb_left;
		} else if (cmp > 0) {
			node = node->rb_right;
		} else {
			rc = --entry->refcount;

			if (rc == 0) {
				rb_erase(&entry->node, &nf->refcount);
				kfree(entry);
			}

			return rc;
		}
	}

	return -ENOENT;
}

static void ssam_nf_call(struct ssam_nf *nf, struct device *dev, u16 rqid,
			 struct ssam_event *event)
{
	struct ssam_nf_head *nf_head;
	int status, nf_ret;

	if (!ssh_rqid_is_event(rqid)) {
		dev_warn(dev, "event: unsupported rqid: 0x%04x\n", rqid);
		return;
	}

	nf_head = &nf->head[ssh_rqid_to_event(rqid)];
	nf_ret = ssam_nfblk_call_chain(nf_head, event);
	status = ssam_notifier_to_errno(nf_ret);

	if (status < 0) {
		dev_err(dev, "event: error handling event: %d "
			"(tc: 0x%02x, cid: 0x%02x, iid: 0x%02x, chn: 0x%02x)\n",
			status, event->target_category, event->command_id,
			event->instance_id, event->channel);
	}

	if (!(nf_ret & SSAM_NOTIF_HANDLED)) {
		dev_warn(dev, "event: unhandled event (rqid: 0x%02x, "
			 "tc: 0x%02x, cid: 0x%02x, iid: 0x%02x, chn: 0x%02x)\n",
			 rqid, event->target_category, event->command_id,
			 event->instance_id, event->channel);
	}
}

static int ssam_nf_register(struct ssam_nf *nf, struct ssam_event_notifier *n)
{
	u16 rqid = ssh_tc_to_rqid(n->event.id.target_category);
	struct ssam_nf_head *nf_head;
	int rc, status;

	if (!ssh_rqid_is_event(rqid))
		return -EINVAL;

	nf_head = &nf->head[ssh_rqid_to_event(rqid)];

	mutex_lock(&nf->lock);

	rc = ssam_nf_refcount_inc(nf, n->event.reg, n->event.id);
	if (rc < 0) {
		mutex_lock(&nf->lock);
		return rc;
	}

	status = __ssam_nfblk_insert(nf_head, &n->base);
	if (status)
		ssam_nf_refcount_dec(nf, n->event.reg, n->event.id);

	mutex_unlock(&nf->lock);
	return status;
}

static int ssam_nf_unregister(struct ssam_nf *nf, struct ssam_event_notifier *n)
{
	u16 rqid = ssh_tc_to_rqid(n->event.id.target_category);
	struct ssam_nf_head *nf_head;
	int status;

	if (!ssh_rqid_is_event(rqid))
		return -EINVAL;

	nf_head = &nf->head[ssh_rqid_to_event(rqid)];

	mutex_lock(&nf->lock);

	status = __ssam_nfblk_remove(nf_head, &n->base);
	if (status) {
		mutex_unlock(&nf->lock);
		return status;
	}

	ssam_nf_refcount_dec(nf, n->event.reg, n->event.id);

	mutex_unlock(&nf->lock);
	synchronize_srcu(&nf_head->srcu);

	return 0;
}

static int ssam_nf_init(struct ssam_nf *nf)
{
	int i, status;

	for (i = 0; i < SURFACE_SAM_SSH_NUM_EVENTS; i++) {
		status = ssam_nf_head_init(&nf->head[i]);
		if (status)
			break;
	}

	if (status) {
		for (i = i - 1; i >= 0; i--)
			ssam_nf_head_destroy(&nf->head[i]);

		return status;
	}

	mutex_init(&nf->lock);
	return 0;
}

static void ssam_nf_destroy(struct ssam_nf *nf)
{
	int i;

	for (i = 0; i < SURFACE_SAM_SSH_NUM_EVENTS; i++)
		ssam_nf_head_destroy(&nf->head[i]);

	mutex_destroy(&nf->lock);
}


/* -- Event/async request completion system. -------------------------------- */

#define SSAM_CPLT_WQ_NAME	"ssam_cpltq"


struct ssam_cplt;

struct ssam_event_item {
	struct list_head node;
	u16 rqid;
	struct ssam_event event;	// must be last
};

struct ssam_event_queue {
	struct ssam_cplt *cplt;

	spinlock_t lock;
	struct list_head head;
	struct work_struct work;
};

struct ssam_event_channel {
	struct ssam_event_queue queue[SURFACE_SAM_SSH_NUM_EVENTS];
};

struct ssam_cplt {
	struct device *dev;
	struct workqueue_struct *wq;

	struct {
		struct ssam_event_channel channel[SURFACE_SAM_SSH_NUM_CHANNELS];
		struct ssam_nf notif;
	} event;
};


static void ssam_event_queue_push(struct ssam_event_queue *q,
				  struct ssam_event_item *item)
{
	spin_lock(&q->lock);
	list_add_tail(&item->node, &q->head);
	spin_unlock(&q->lock);
}

static struct ssam_event_item *ssam_event_queue_pop(struct ssam_event_queue *q)
{
	struct ssam_event_item *item;

	spin_lock(&q->lock);
	item = list_first_entry_or_null(&q->head, struct ssam_event_item, node);
	if (item)
		list_del(&item->node);
	spin_unlock(&q->lock);

	return item;
}

static bool ssam_event_queue_is_empty(struct ssam_event_queue *q)
{
	bool empty;

	spin_lock(&q->lock);
	empty = list_empty(&q->head);
	spin_unlock(&q->lock);

	return empty;
}

static struct ssam_event_queue *ssam_cplt_get_event_queue(
		struct ssam_cplt *cplt, u8 channel, u16 rqid)
{
	u16 event = ssh_rqid_to_event(rqid);
	u16 chidx = ssh_channel_to_index(channel);

	if (!ssh_rqid_is_event(rqid)) {
		dev_err(cplt->dev, "event: unsupported rqid: 0x%04x\n", rqid);
		return NULL;
	}

	if (!ssh_channel_is_valid(channel)) {
		dev_warn(cplt->dev, "event: unsupported channel: %u\n",
			 channel);
		chidx = 0;
	}

	return &cplt->event.channel[chidx].queue[event];
}

static inline bool ssam_cplt_submit(struct ssam_cplt *cplt,
				    struct work_struct *work)
{
	return queue_work(cplt->wq, work);
}

static int ssam_cplt_submit_event(struct ssam_cplt *cplt,
				  struct ssam_event_item *item)
{
	struct ssam_event_queue *evq;

	evq = ssam_cplt_get_event_queue(cplt, item->event.channel, item->rqid);
	if (!evq)
		return -EINVAL;

	ssam_event_queue_push(evq, item);
	ssam_cplt_submit(cplt, &evq->work);
	return 0;
}

static void ssam_cplt_flush(struct ssam_cplt *cplt)
{
	flush_workqueue(cplt->wq);
}

static void ssam_event_queue_work_fn(struct work_struct *work)
{
	struct ssam_event_queue *queue;
	struct ssam_event_item *item;
	struct ssam_nf *nf;
	struct device *dev;
	int i;

	queue = container_of(work, struct ssam_event_queue, work);
	nf = &queue->cplt->event.notif;
	dev = queue->cplt->dev;

	for (i = 0; i < 10; i++) {
		item = ssam_event_queue_pop(queue);
		if (item == NULL)
			return;

		ssam_nf_call(nf, dev, item->rqid, &item->event);
		kfree(item);
	}

	if (!ssam_event_queue_is_empty(queue))
		ssam_cplt_submit(queue->cplt, &queue->work);
}

static void ssam_event_queue_init(struct ssam_cplt *cplt,
				  struct ssam_event_queue *evq)
{
	evq->cplt = cplt;
	spin_lock_init(&evq->lock);
	INIT_LIST_HEAD(&evq->head);
	INIT_WORK(&evq->work, ssam_event_queue_work_fn);
}

static int ssam_cplt_init(struct ssam_cplt *cplt, struct device *dev)
{
	struct ssam_event_channel *channel;
	int status, c, i;

	cplt->dev = dev;

	cplt->wq = create_workqueue(SSAM_CPLT_WQ_NAME);
	if (!cplt->wq)
		return -ENOMEM;

	for (c = 0; c < ARRAY_SIZE(cplt->event.channel); c++) {
		channel = &cplt->event.channel[c];

		for (i = 0; i < ARRAY_SIZE(channel->queue); i++)
			ssam_event_queue_init(cplt, &channel->queue[i]);
	}

	status = ssam_nf_init(&cplt->event.notif);
	if (status)
		destroy_workqueue(cplt->wq);

	return status;
}

static void ssam_cplt_destroy(struct ssam_cplt *cplt)
{
	destroy_workqueue(cplt->wq);
	ssam_nf_destroy(&cplt->event.notif);
}


/* -- Top-Level Request Interface ------------------------------------------- */

struct ssam_response {
	int status;
	u16 capacity;
	u16 length;
	u8 *pointer;
};

struct ssam_request_sync {
	struct ssh_request base;
	struct completion comp;
	struct ssam_response resp;
};


static void ssam_request_sync_complete(struct ssh_request *rqst,
				       const struct ssh_command *cmd,
				       const struct sshp_span *data, int status)
{
	struct ssam_request_sync *r;
	struct ssh_rtl *rtl = READ_ONCE(rqst->rtl);

	r = container_of(rqst, struct ssam_request_sync, base);
	r->resp.status = status;
	r->resp.length = 0;

	if (status) {
		rtl_dbg_cond(rtl, "rsp: request failed: %d\n", status);
		return;
	}

	if (!data)	// handle requests without a response
		return;

	if (!r->resp.pointer && data->len) {
		rtl_warn(rtl, "rsp: no response buffer provided, dropping data\n");
		return;
	}

	if (data->len > r->resp.capacity) {
		rtl_err(rtl, "rsp: response buffer too small,"
			" capacity: %u bytes, got: %zu bytes\n",
			r->resp.capacity, data->len);
		status = -ENOSPC;
		return;
	}

	r->resp.length = data->len;
	memcpy(r->resp.pointer, data->ptr, data->len);
}

static void ssam_request_sync_release(struct ssh_request *rqst)
{
	complete_all(&container_of(rqst, struct ssam_request_sync, base)->comp);
}

static const struct ssh_request_ops ssam_request_sync_ops = {
	.release = ssam_request_sync_release,
	.complete = ssam_request_sync_complete,
};

static void ssam_request_sync_wait_complete(struct ssam_request_sync *rqst)
{
	wait_for_completion(&rqst->comp);
}


/* -- TODO ------------------------------------------------------------------ */

enum ssh_ec_state {
	SSH_EC_UNINITIALIZED,
	SSH_EC_INITIALIZED,
	SSH_EC_SUSPENDED,
};

struct sam_ssh_ec {
	struct serdev_device *serdev;

	struct ssh_rtl rtl;
	struct ssam_cplt cplt;

	struct {
		struct ssh_seq_counter seq;
		struct ssh_rqid_counter rqid;
	} counter;

	enum ssh_ec_state state;

	int irq;
	bool irq_wakeup_enabled;
};

static struct sam_ssh_ec ssh_ec = {
	.state  = SSH_EC_UNINITIALIZED,
	.serdev = NULL,
};


/* -- TODO ------------------------------------------------------------------ */

#define ssh_dbg(ec, fmt, ...)  dev_dbg(&(ec)->serdev->dev, fmt, ##__VA_ARGS__)
#define ssh_warn(ec, fmt, ...) dev_warn(&(ec)->serdev->dev, fmt, ##__VA_ARGS__)
#define ssh_err(ec, fmt, ...)  dev_err(&(ec)->serdev->dev, fmt, ##__VA_ARGS__)


static inline struct sam_ssh_ec *surface_sam_ssh_acquire(void)
{
	return &ssh_ec;
}

static inline struct sam_ssh_ec *surface_sam_ssh_acquire_init(void)
{
	struct sam_ssh_ec *ec = surface_sam_ssh_acquire();

	if (smp_load_acquire(&ec->state) == SSH_EC_UNINITIALIZED)
		return NULL;

	return ec;
}

int surface_sam_ssh_consumer_register(struct device *consumer)
{
	u32 flags = DL_FLAG_PM_RUNTIME | DL_FLAG_AUTOREMOVE_CONSUMER;
	struct sam_ssh_ec *ec;
	struct device_link *link;

	ec = surface_sam_ssh_acquire_init();
	if (!ec)
		return -ENXIO;

	link = device_link_add(consumer, &ec->serdev->dev, flags);
	if (!link)
		return -EFAULT;

	return 0;
}
EXPORT_SYMBOL_GPL(surface_sam_ssh_consumer_register);


static int __surface_sam_ssh_rqst(struct sam_ssh_ec *ec,
				  const struct surface_sam_ssh_rqst *rqst,
				  struct surface_sam_ssh_buf *result);

static int surface_sam_ssh_event_enable(struct sam_ssh_ec *ec,
					struct ssam_event_registry reg,
					struct ssam_event_id id,
					u8 flags)
{
	struct ssh_notification_params params;
	struct surface_sam_ssh_rqst rqst;
	struct surface_sam_ssh_buf result;

	u16 rqid = ssh_tc_to_rqid(id.target_category);
	u8 buf[1] = { 0x00 };
	int status;

	// only allow RQIDs that lie within event spectrum
	if (!ssh_rqid_is_event(rqid))
		return -EINVAL;

	params.target_category = id.target_category;
	params.instance_id = id.instance;
	params.flags = flags;
	put_unaligned_le16(rqid, &params.request_id);

	rqst.tc = reg.target_category;
	rqst.cid = reg.cid_enable;
	rqst.iid = 0x00;
	rqst.chn = reg.channel;
	rqst.snc = 0x01;
	rqst.cdl = sizeof(params);
	rqst.pld = (u8 *)&params;

	result.cap = ARRAY_SIZE(buf);
	result.len = 0;
	result.data = buf;

	status = __surface_sam_ssh_rqst(ec, &rqst, &result);

	if (status) {
		dev_err(&ec->serdev->dev, "failed to enable event source"
			" (tc: 0x%02x, rqid: 0x%04x)\n",
			id.target_category, rqid);
	}

	if (buf[0] != 0x00) {
		pr_warn(SSH_RQST_TAG_FULL
			"unexpected result while enabling event source: "
			"0x%02x\n", buf[0]);
	}

	return status;

}

static int surface_sam_ssh_event_disable(struct sam_ssh_ec *ec,
					 struct ssam_event_registry reg,
					 struct ssam_event_id id,
					 u8 flags)
{
	struct ssh_notification_params params;
	struct surface_sam_ssh_rqst rqst;
	struct surface_sam_ssh_buf result;

	u16 rqid = ssh_tc_to_rqid(id.target_category);
	u8 buf[1] = { 0x00 };
	int status;

	// only allow RQIDs that lie within event spectrum
	if (!ssh_rqid_is_event(rqid))
		return -EINVAL;

	params.target_category = id.target_category;
	params.instance_id = id.instance;
	params.flags = flags;
	put_unaligned_le16(rqid, &params.request_id);

	rqst.tc = reg.target_category;
	rqst.cid = reg.cid_disable;
	rqst.iid = 0x00;
	rqst.chn = reg.channel;
	rqst.snc = 0x01;
	rqst.cdl = sizeof(params);
	rqst.pld = (u8 *)&params;

	result.cap = ARRAY_SIZE(buf);
	result.len = 0;
	result.data = buf;

	status = __surface_sam_ssh_rqst(ec, &rqst, &result);

	if (status) {
		dev_err(&ec->serdev->dev, "failed to disable event source"
			" (tc: 0x%02x, rqid: 0x%04x)\n",
			id.target_category, rqid);
	}

	if (buf[0] != 0x00) {
		dev_warn(&ec->serdev->dev,
			"unexpected result while disabling event source: "
			"0x%02x\n", buf[0]);
	}

	return status;
}


int surface_sam_ssh_notifier_register(struct ssam_event_notifier *n)
{
	struct ssam_nf_head *nf_head;
	struct sam_ssh_ec *ec;
	struct ssam_nf *nf;
	u16 event = ssh_tc_to_event(n->event.id.target_category);
	u16 rqid = ssh_event_to_rqid(event);
	int rc, status;

	if (!ssh_rqid_is_event(rqid))
		return -EINVAL;

	ec = surface_sam_ssh_acquire_init();
	if (!ec)
		return -ENXIO;

	nf = &ec->cplt.event.notif;
	nf_head = &nf->head[event];

	mutex_lock(&nf->lock);

	rc = ssam_nf_refcount_inc(nf, n->event.reg, n->event.id);
	if (rc < 0) {
		mutex_unlock(&nf->lock);
		return rc;
	}

	ssh_dbg(ec, "enabling event (tc: 0x%02x, rc: %d)\n", rqid, rc);

	status = __ssam_nfblk_insert(nf_head, &n->base);
	if (status) {
		ssam_nf_refcount_dec(nf, n->event.reg, n->event.id);
		mutex_unlock(&nf->lock);
		return status;
	}

	if (rc == 1) {
		status = surface_sam_ssh_event_enable(ec, n->event.reg, n->event.id, n->event.flags);
		if (status) {
			__ssam_nfblk_remove(nf_head, &n->base);
			ssam_nf_refcount_dec(nf, n->event.reg, n->event.id);
			mutex_unlock(&nf->lock);
			return status;
		}
	}

	mutex_unlock(&nf->lock);
	return 0;
}
EXPORT_SYMBOL_GPL(surface_sam_ssh_notifier_register);

int surface_sam_ssh_notifier_unregister(struct ssam_event_notifier *n)
{
	struct ssam_nf_head *nf_head;
	struct sam_ssh_ec *ec;
	struct ssam_nf *nf;
	u16 event = ssh_tc_to_event(n->event.id.target_category);
	u16 rqid = ssh_event_to_rqid(event);
	int rc, status = 0;

	if (!ssh_rqid_is_event(rqid))
		return -EINVAL;

	ec = surface_sam_ssh_acquire_init();
	if (!ec)
		return -ENXIO;

	nf = &ec->cplt.event.notif;
	nf_head = &nf->head[event];

	mutex_lock(&nf->lock);

	rc = ssam_nf_refcount_dec(nf, n->event.reg, n->event.id);
	if (rc < 0) {
		mutex_unlock(&nf->lock);
		return rc;
	}

	ssh_dbg(ec, "disabling event (tc: 0x%02x, rc: %d)\n", rqid, rc);

	if (rc == 0)
		status = surface_sam_ssh_event_disable(ec, n->event.reg, n->event.id, n->event.flags);

	__ssam_nfblk_remove(nf_head, &n->base);
	mutex_unlock(&nf->lock);
	synchronize_srcu(&nf_head->srcu);

	return status;
}
EXPORT_SYMBOL_GPL(surface_sam_ssh_notifier_unregister);


static int __surface_sam_ssh_rqst(struct sam_ssh_ec *ec,
				  const struct surface_sam_ssh_rqst *rqst,
				  struct surface_sam_ssh_buf *result)
{
	struct ssam_request_sync actual;
	struct msgbuf msgb;
	size_t msglen = SSH_COMMAND_MESSAGE_LENGTH(rqst->cdl);
	unsigned flags = 0;
	u16 rqid;
	u8 seq;
	int status;

	// prevent overflow
	if (rqst->cdl > SSH_COMMAND_MAX_PAYLOAD_SIZE) {
		ssh_err(ec, SSH_RQST_TAG "request payload too large\n");
		return -EINVAL;
	}

	if (result && result->data && rqst->snc)
		flags |= SSAM_REQUEST_HAS_RESPONSE;

	ssh_request_init(&actual.base, flags, &ssam_request_sync_ops);
	init_completion(&actual.comp);

	actual.resp.pointer = NULL;
	actual.resp.capacity = 0;
	actual.resp.length = 0;
	actual.resp.status = 0;

	if (result) {
		actual.resp.pointer = result->data;
		actual.resp.capacity = result->cap;
	}

	// alloc and create message
	status = msgb_alloc(&msgb, msglen, GFP_KERNEL);
	if (status)
		return status;

	seq = ssh_seq_next(&ec->counter.seq);
	rqid = ssh_rqid_next(&ec->counter.rqid);
	msgb_push_cmd(&msgb, seq, rqst, rqid);

	actual.base.packet.data = msgb.buffer;
	actual.base.packet.data_length = msgb.ptr - msgb.buffer;

	status = ssh_rtl_submit(&ec->rtl, &actual.base);
	if (status) {
		msgb_free(&msgb);
		return status;
	}

	ssh_request_put(&actual.base);
	ssam_request_sync_wait_complete(&actual);
	msgb_free(&msgb);

	if (result)
		result->len = actual.resp.length;

	return actual.resp.status;
}

int surface_sam_ssh_rqst(const struct surface_sam_ssh_rqst *rqst, struct surface_sam_ssh_buf *result)
{
	struct sam_ssh_ec *ec;

	ec = surface_sam_ssh_acquire_init();
	if (!ec) {
		pr_warn(SSH_RQST_TAG_FULL "embedded controller is uninitialized\n");
		return -ENXIO;
	}

	if (smp_load_acquire(&ec->state) == SSH_EC_SUSPENDED) {
		ssh_warn(ec, SSH_RQST_TAG "embedded controller is suspended\n");
		return -EPERM;
	}

	return __surface_sam_ssh_rqst(ec, rqst, result);
}
EXPORT_SYMBOL_GPL(surface_sam_ssh_rqst);


/**
 * surface_sam_ssh_ec_resume - Resume the EC if it is in a suspended mode.
 * @ec: the EC to resume
 *
 * Moves the EC from a suspended state to a normal state. See the
 * `surface_sam_ssh_ec_suspend` function what the specific differences of
 * these states are. Multiple repeated calls to this function seem to be
 * handled fine by the EC, after the first call, the state will remain
 * "normal".
 *
 * Must be called with the EC initialized and its lock held.
 */
static int surface_sam_ssh_ec_resume(struct sam_ssh_ec *ec)
{
	u8 buf[1] = { 0x00 };
	int status;

	struct surface_sam_ssh_rqst rqst = {
		.tc  = 0x01,
		.cid = 0x16,
		.iid = 0x00,
		.chn = 0x01,
		.snc = 0x01,
		.cdl = 0x00,
		.pld = NULL,
	};

	struct surface_sam_ssh_buf result = {
		result.cap = ARRAY_SIZE(buf),
		result.len = 0,
		result.data = buf,
	};

	ssh_dbg(ec, "pm: resuming system aggregator module\n");
	status = __surface_sam_ssh_rqst(ec, &rqst, &result);
	if (status)
		return status;

	/*
	 * The purpose of the return value of this request is unknown. Based on
	 * logging and experience, we expect it to be zero. No other value has
	 * been observed so far.
	 */
	if (buf[0] != 0x00) {
		ssh_warn(ec, "unexpected result while trying to resume EC: "
			 "0x%02x\n", buf[0]);
	}

	return 0;
}

/**
 * surface_sam_ssh_ec_suspend - Put the EC in a suspended mode:
 * @ec: the EC to suspend
 *
 * Tells the EC to enter a suspended mode. In this mode, events are quiesced
 * and the wake IRQ is armed (note that the wake IRQ does not fire if the EC
 * has not been suspended via this request). On some devices, the keyboard
 * backlight is turned off. Apart from this, the EC seems to continue to work
 * as normal, meaning requests sent to it are acknowledged and seem to be
 * correctly handled, including potential responses. Multiple repeated calls
 * to this function seem to be handled fine by the EC, after the first call,
 * the state will remain "suspended".
 *
 * Must be called with the EC initialized and its lock held.
 */
static int surface_sam_ssh_ec_suspend(struct sam_ssh_ec *ec)
{
	u8 buf[1] = { 0x00 };
	int status;

	struct surface_sam_ssh_rqst rqst = {
		.tc  = 0x01,
		.cid = 0x15,
		.iid = 0x00,
		.chn = 0x01,
		.snc = 0x01,
		.cdl = 0x00,
		.pld = NULL,
	};

	struct surface_sam_ssh_buf result = {
		result.cap = ARRAY_SIZE(buf),
		result.len = 0,
		result.data = buf,
	};

	ssh_dbg(ec, "pm: suspending system aggregator module\n");
	status = __surface_sam_ssh_rqst(ec, &rqst, &result);
	if (status)
		return status;

	/*
	 * The purpose of the return value of this request is unknown. Based on
	 * logging and experience, we expect it to be zero. No other value has
	 * been observed so far.
	 */
	if (buf[0] != 0x00) {
		ssh_warn(ec, "unexpected result while trying to suspend EC: "
			 "0x%02x\n", buf[0]);
	}

	return 0;
}


static int surface_sam_ssh_get_controller_version(struct sam_ssh_ec *ec, u32 *version)
{
	struct surface_sam_ssh_rqst rqst = {
		.tc  = 0x01,
		.cid = 0x13,
		.iid = 0x00,
		.chn = 0x01,
		.snc = 0x01,
		.cdl = 0x00,
		.pld = NULL,
	};

	struct surface_sam_ssh_buf result = {
		result.cap = sizeof(*version),
		result.len = 0,
		result.data = (u8 *)version,
	};

	*version = 0;
	return __surface_sam_ssh_rqst(ec, &rqst, &result);
}

static int surface_sam_ssh_log_controller_version(struct sam_ssh_ec *ec)
{
	u32 version, a, b, c;
	int status;

	status = surface_sam_ssh_get_controller_version(ec, &version);
	if (status)
		return status;

	a = (version >> 24) & 0xff;
	b = le16_to_cpu((version >> 8) & 0xffff);
	c = version & 0xff;

	dev_info(&ec->serdev->dev, "SAM controller version: %u.%u.%u\n",
		 a, b, c);
	return 0;
}


static const struct acpi_gpio_params gpio_ssh_wakeup_int = { 0, 0, false };
static const struct acpi_gpio_params gpio_ssh_wakeup     = { 1, 0, false };

static const struct acpi_gpio_mapping ssh_acpi_gpios[] = {
	{ "ssh_wakeup-int-gpio", &gpio_ssh_wakeup_int, 1 },
	{ "ssh_wakeup-gpio",     &gpio_ssh_wakeup,     1 },
	{ },
};

static irqreturn_t ssh_wake_irq_handler(int irq, void *dev_id)
{
	struct serdev_device *serdev = dev_id;

	dev_dbg(&serdev->dev, "pm: wake irq triggered\n");

	// TODO: Send GPIO callback command repeatedly to EC until callback
	//       returns 0x00. Return flag of callback is "has more events".
	//       Each time the command is sent, one event is "released". Once
	//       all events have been released (return = 0x00), the GPIO is
	//       re-armed.

	return IRQ_HANDLED;
}

static int ssh_setup_irq(struct serdev_device *serdev)
{
	const int irqf = IRQF_SHARED | IRQF_ONESHOT | IRQF_TRIGGER_RISING;
	struct gpio_desc *gpiod;
	int irq;
	int status;

	gpiod = gpiod_get(&serdev->dev, "ssh_wakeup-int", GPIOD_ASIS);
	if (IS_ERR(gpiod))
		return PTR_ERR(gpiod);

	irq = gpiod_to_irq(gpiod);
	gpiod_put(gpiod);

	if (irq < 0)
		return irq;

	status = request_threaded_irq(irq, NULL, ssh_wake_irq_handler,
				      irqf, "surface_sam_sh_wakeup", serdev);
	if (status)
		return status;

	return irq;
}


static acpi_status ssh_setup_from_resource(struct acpi_resource *rsc, void *ctx)
{
	struct serdev_device *serdev = ctx;
	struct acpi_resource_common_serialbus *serial;
	struct acpi_resource_uart_serialbus *uart;
	bool flow_control;
	int status = 0;

	if (rsc->type != ACPI_RESOURCE_TYPE_SERIAL_BUS)
		return AE_OK;

	serial = &rsc->data.common_serial_bus;
	if (serial->type != ACPI_RESOURCE_SERIAL_TYPE_UART)
		return AE_OK;

	uart = &rsc->data.uart_serial_bus;

	// set up serdev device
	serdev_device_set_baudrate(serdev, uart->default_baud_rate);

	// serdev currently only supports RTSCTS flow control
	if (uart->flow_control & SSH_SUPPORTED_FLOW_CONTROL_MASK) {
		dev_warn(&serdev->dev, "setup: unsupported flow control"
			 " (value: 0x%02x)\n", uart->flow_control);
	}

	// set RTSCTS flow control
	flow_control = uart->flow_control & ACPI_UART_FLOW_CONTROL_HW;
	serdev_device_set_flow_control(serdev, flow_control);

	// serdev currently only supports EVEN/ODD parity
	switch (uart->parity) {
	case ACPI_UART_PARITY_NONE:
		status = serdev_device_set_parity(serdev, SERDEV_PARITY_NONE);
		break;
	case ACPI_UART_PARITY_EVEN:
		status = serdev_device_set_parity(serdev, SERDEV_PARITY_EVEN);
		break;
	case ACPI_UART_PARITY_ODD:
		status = serdev_device_set_parity(serdev, SERDEV_PARITY_ODD);
		break;
	default:
		dev_warn(&serdev->dev, "setup: unsupported parity"
			 " (value: 0x%02x)\n", uart->parity);
		break;
	}

	if (status) {
		dev_err(&serdev->dev, "setup: failed to set parity"
			" (value: 0x%02x)\n", uart->parity);
		return status;
	}

	return AE_CTRL_TERMINATE;       // we've found the resource and are done
}


static int surface_sam_ssh_suspend(struct device *dev)
{
	struct sam_ssh_ec *ec;
	int status;

	dev_dbg(dev, "pm: suspending\n");

	ec = surface_sam_ssh_acquire_init();
	if (ec) {
		status = surface_sam_ssh_ec_suspend(ec);
		if (status)
			return status;

		if (device_may_wakeup(dev)) {
			status = enable_irq_wake(ec->irq);
			if (status)
				return status;

			ec->irq_wakeup_enabled = true;
		} else {
			ec->irq_wakeup_enabled = false;
		}

		smp_store_release(&ec->state, SSH_EC_SUSPENDED);
	}

	return 0;
}

static int surface_sam_ssh_resume(struct device *dev)
{
	struct sam_ssh_ec *ec;
	int status;

	dev_dbg(dev, "pm: resuming\n");

	ec = surface_sam_ssh_acquire_init();
	if (ec) {
		smp_store_release(&ec->state, SSH_EC_INITIALIZED);

		if (ec->irq_wakeup_enabled) {
			status = disable_irq_wake(ec->irq);
			if (status)
				return status;

			ec->irq_wakeup_enabled = false;
		}

		status = surface_sam_ssh_ec_resume(ec);
		if (status)
			return status;
	}

	return 0;
}

static SIMPLE_DEV_PM_OPS(surface_sam_ssh_pm_ops, surface_sam_ssh_suspend,
			 surface_sam_ssh_resume);


static void ssam_handle_event(struct ssh_rtl *rtl,
			      const struct ssh_command *cmd,
			      const struct sshp_span *data)
{
	struct sam_ssh_ec *ec = container_of(rtl, struct sam_ssh_ec, rtl);
	struct ssam_event_item *item;

	item = kzalloc(sizeof(struct ssam_event_item) + data->len, GFP_KERNEL);
	if (!item)
		return;

	item->rqid = get_unaligned_le16(&cmd->rqid);
	item->event.target_category = cmd->tc;
	item->event.command_id = cmd->cid;
	item->event.instance_id = cmd->iid;
	item->event.channel = cmd->chn_in;
	item->event.length  = data->len;
	memcpy(&item->event.data[0], data->ptr, data->len);

	ssam_cplt_submit_event(&ec->cplt, item);
}

static struct ssh_rtl_ops ssam_rtl_ops = {
	.handle_event = ssam_handle_event,
};


static int ssam_receive_buf(struct serdev_device *dev, const unsigned char *buf, size_t n)
{
	struct sam_ssh_ec *ec = serdev_device_get_drvdata(dev);
	return ssh_ptl_rx_rcvbuf(&ec->rtl.ptl, buf, n);
}

static void ssam_write_wakeup(struct serdev_device *dev)
{
	struct sam_ssh_ec *ec = serdev_device_get_drvdata(dev);
	ssh_ptl_tx_wakeup(&ec->rtl.ptl, true);
}

struct serdev_device_ops ssam_serdev_ops = {
	.receive_buf = ssam_receive_buf,
	.write_wakeup = ssam_write_wakeup,
};


#ifdef CONFIG_SURFACE_SAM_SSH_DEBUG_DEVICE

static char sam_ssh_debug_rqst_buf_sysfs[256] = { 0 };
static char sam_ssh_debug_rqst_buf_pld[255] = { 0 };
static char sam_ssh_debug_rqst_buf_res[255] = { 0 };

struct sysfs_rqst {
	u8 tc;
	u8 cid;
	u8 iid;
	u8 chn;
	u8 snc;
	u8 cdl;
	u8 pld[0];
} __packed;

static ssize_t rqst_read(struct file *f, struct kobject *kobj, struct bin_attribute *attr,
			 char *buf, loff_t offs, size_t count)
{
	if (offs < 0 || count + offs > ARRAY_SIZE(sam_ssh_debug_rqst_buf_sysfs))
		return -EINVAL;

	memcpy(buf, sam_ssh_debug_rqst_buf_sysfs + offs, count);
	return count;
}

static ssize_t rqst_write(struct file *f, struct kobject *kobj, struct bin_attribute *attr,
			  char *buf, loff_t offs, size_t count)
{
	struct sysfs_rqst *input;
	struct surface_sam_ssh_rqst rqst = {};
	struct surface_sam_ssh_buf result = {};
	int status;

	// check basic write constriants
	if (offs != 0 || count - sizeof(struct sysfs_rqst) > ARRAY_SIZE(sam_ssh_debug_rqst_buf_pld))
		return -EINVAL;

	if (count < sizeof(struct sysfs_rqst))
		return -EINVAL;

	input = (struct sysfs_rqst *)buf;

	// payload length should be consistent with data provided
	if (input->cdl + sizeof(struct sysfs_rqst) != count)
		return -EINVAL;

	rqst.tc  = input->tc;
	rqst.cid = input->cid;
	rqst.iid = input->iid;
	rqst.chn = input->chn;
	rqst.snc = input->snc;
	rqst.cdl = input->cdl;
	rqst.pld = sam_ssh_debug_rqst_buf_pld;
	memcpy(sam_ssh_debug_rqst_buf_pld, &input->pld[0], input->cdl);

	result.cap = ARRAY_SIZE(sam_ssh_debug_rqst_buf_res);
	result.len = 0;
	result.data = sam_ssh_debug_rqst_buf_res;

	status = surface_sam_ssh_rqst(&rqst, &result);
	if (status)
		return status;

	sam_ssh_debug_rqst_buf_sysfs[0] = result.len;
	memcpy(sam_ssh_debug_rqst_buf_sysfs + 1, result.data, result.len);
	memset(sam_ssh_debug_rqst_buf_sysfs + result.len + 1, 0,
	       ARRAY_SIZE(sam_ssh_debug_rqst_buf_sysfs) + 1 - result.len);

	return count;
}

static const BIN_ATTR_RW(rqst, ARRAY_SIZE(sam_ssh_debug_rqst_buf_sysfs));

static int surface_sam_ssh_sysfs_register(struct device *dev)
{
	return sysfs_create_bin_file(&dev->kobj, &bin_attr_rqst);
}

static void surface_sam_ssh_sysfs_unregister(struct device *dev)
{
	sysfs_remove_bin_file(&dev->kobj, &bin_attr_rqst);
}

#else /* CONFIG_SURFACE_SAM_SSH_DEBUG_DEVICE */

static int surface_sam_ssh_sysfs_register(struct device *dev)
{
	return 0;
}

static void surface_sam_ssh_sysfs_unregister(struct device *dev)
{
}

#endif /* CONFIG_SURFACE_SAM_SSH_DEBUG_DEVICE */


static int surface_sam_ssh_probe(struct serdev_device *serdev)
{
	struct sam_ssh_ec *ec;
	acpi_handle *ssh = ACPI_HANDLE(&serdev->dev);
	int status, irq;

	if (gpiod_count(&serdev->dev, NULL) < 0)
		return -ENODEV;

	status = devm_acpi_dev_add_driver_gpios(&serdev->dev, ssh_acpi_gpios);
	if (status)
		return status;

	// setup IRQ
	irq = ssh_setup_irq(serdev);
	if (irq < 0)
		return irq;

	// set up EC
	ec = surface_sam_ssh_acquire();
	if (smp_load_acquire(&ec->state) != SSH_EC_UNINITIALIZED) {
		dev_err(&serdev->dev, "embedded controller already initialized\n");

		status = -EBUSY;
		goto err_ecinit;
	}

	ec->serdev = serdev;
	ec->irq    = irq;
	ssh_seq_reset(&ec->counter.seq);
	ssh_rqid_reset(&ec->counter.rqid);

	// initialize event/request completion system
	status = ssam_cplt_init(&ec->cplt, &serdev->dev);
	if (status)
		goto err_ecinit;

	// initialize request and packet transmission layers
	status = ssh_rtl_init(&ec->rtl, serdev, &ssam_rtl_ops);
	if (status)
		goto err_rtl;

	serdev_device_set_drvdata(serdev, ec);

	serdev_device_set_client_ops(serdev, &ssam_serdev_ops);
	status = serdev_device_open(serdev);
	if (status)
		goto err_open;

	status = acpi_walk_resources(ssh, METHOD_NAME__CRS,
				     ssh_setup_from_resource, serdev);
	if (ACPI_FAILURE(status))
		goto err_devinit;

	status = ssh_rtl_tx_start(&ec->rtl);
	if (status)
		goto err_devinit;

	status = ssh_rtl_rx_start(&ec->rtl);
	if (status)
		goto err_devinit;

	smp_store_release(&ec->state, SSH_EC_INITIALIZED);

	status = surface_sam_ssh_log_controller_version(ec);
	if (status)
		goto err_finalize;

	status = surface_sam_ssh_ec_resume(ec);
	if (status)
		goto err_finalize;

	status = surface_sam_ssh_sysfs_register(&serdev->dev);
	if (status)
		goto err_finalize;

	// TODO: The EC can wake up the system via the associated GPIO interrupt in
	// multiple situations. One of which is the remaining battery capacity
	// falling below a certain threshold. Normally, we should use the
	// device_init_wakeup function, however, the EC also seems to have other
	// reasons for waking up the system and it seems that Windows has
	// additional checks whether the system should be resumed. In short, this
	// causes some spourious unwanted wake-ups. For now let's thus default
	// power/wakeup to false.
	device_set_wakeup_capable(&serdev->dev, true);
	acpi_walk_dep_device_list(ssh);

	return 0;

err_finalize:
	smp_store_release(&ec->state, SSH_EC_UNINITIALIZED);
	ssh_rtl_flush(&ec->rtl, msecs_to_jiffies(5000));
err_devinit:
	serdev_device_close(serdev);
err_open:
	ssh_rtl_shutdown(&ec->rtl);
	ssh_rtl_destroy(&ec->rtl);
err_rtl:
	ssam_cplt_flush(&ec->cplt);
	ssam_cplt_destroy(&ec->cplt);
err_ecinit:
	free_irq(irq, serdev);
	serdev_device_set_drvdata(serdev, NULL);
	return status;
}

static void surface_sam_ssh_remove(struct serdev_device *serdev)
{
	struct sam_ssh_ec *ec;
	int status;

	ec = surface_sam_ssh_acquire_init();
	if (!ec)
		return;

	free_irq(ec->irq, serdev);
	surface_sam_ssh_sysfs_unregister(&serdev->dev);

	// suspend EC and disable events
	status = surface_sam_ssh_ec_suspend(ec);
	if (status)
		dev_err(&serdev->dev, "failed to suspend EC: %d\n", status);

	// flush pending events and requests while everything still works
	status = ssh_rtl_flush(&ec->rtl, msecs_to_jiffies(5000));
	if (status)
		dev_err(&serdev->dev, "failed to flush request transmission layer: %d\n", status);

	ssam_cplt_flush(&ec->cplt);

	// mark device as uninitialized
	smp_store_release(&ec->state, SSH_EC_UNINITIALIZED);

	// cancel rem. requests, ensure no new ones can be queued, stop threads
	ssh_rtl_tx_flush(&ec->rtl);
	ssh_rtl_shutdown(&ec->rtl);

	// shut down actual transport
	serdev_device_wait_until_sent(ec->serdev, 0);
	serdev_device_close(ec->serdev);

	/*
	 * Ensure _all_ events are completed. New ones could still have been
	 * received after the last flush, before the request transport layer
	 * has been shut down. At this point we can be sure that no requests
	 * will remain after this call.
	 */
	ssam_cplt_flush(&ec->cplt);

	// actually free resources
	ssam_cplt_destroy(&ec->cplt);
	ssh_rtl_destroy(&ec->rtl);

	ec->serdev = NULL;
	ec->irq = -1;

	device_set_wakeup_capable(&serdev->dev, false);
	serdev_device_set_drvdata(serdev, NULL);
}


static const struct acpi_device_id surface_sam_ssh_match[] = {
	{ "MSHW0084", 0 },
	{ },
};
MODULE_DEVICE_TABLE(acpi, surface_sam_ssh_match);

static struct serdev_device_driver surface_sam_ssh = {
	.probe = surface_sam_ssh_probe,
	.remove = surface_sam_ssh_remove,
	.driver = {
		.name = "surface_sam_ssh",
		.acpi_match_table = surface_sam_ssh_match,
		.pm = &surface_sam_ssh_pm_ops,
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};


static int __init surface_sam_ssh_init(void)
{
	return serdev_device_driver_register(&surface_sam_ssh);
}

static void __exit surface_sam_ssh_exit(void)
{
	serdev_device_driver_unregister(&surface_sam_ssh);
}

/*
 * Ensure that the driver is loaded late due to some issues with the UART
 * communication. Specifically, we want to ensure that DMA is ready and being
 * used. Not using DMA can result in spurious communication failures,
 * especially during boot, which among other things will result in wrong
 * battery information (via ACPI _BIX) being displayed. Using a late init_call
 * instead of the normal module_init gives the DMA subsystem time to
 * initialize and via that results in a more stable communication, avoiding
 * such failures.
 */
late_initcall(surface_sam_ssh_init);
module_exit(surface_sam_ssh_exit);

MODULE_AUTHOR("Maximilian Luz <luzmaximilian@gmail.com>");
MODULE_DESCRIPTION("Surface Serial Hub Driver for 5th Generation Surface Devices");
MODULE_LICENSE("GPL");
