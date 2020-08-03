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


/* -- Error injection helpers. ---------------------------------------------- */

#ifdef CONFIG_SURFACE_SAM_SSH_ERROR_INJECTION
#define noinline_if_inject noinline
#else /* CONFIG_SURFACE_SAM_SSH_ERROR_INJECTION */
#define noinline_if_inject inline
#endif /* CONFIG_SURFACE_SAM_SSH_ERROR_INJECTION */


/* -- SSH protocol utility functions and definitions. ----------------------- */

/*
 * The number of reserved event IDs, used for registering an SSH event
 * handler. Valid event IDs are numbers below or equal to this value, with
 * exception of zero, which is not an event ID. Thus, this is also the
 * absolute maximum number of event handlers that can be registered.
 */
#define SSH_NUM_EVENTS		34

/*
 * The number of communication channels used in the protocol.
 */
#define SSH_NUM_CHANNELS	2


static inline u16 ssh_crc(const u8 *buf, size_t len)
{
	return crc_ccitt_false(0xffff, buf, len);
}

static inline u16 ssh_rqid_next_valid(u16 rqid)
{
	return rqid > 0 ? rqid + 1u : rqid + SSH_NUM_EVENTS + 1u;
}

static inline u16 ssh_rqid_to_event(u16 rqid)
{
	return rqid - 1u;
}

static inline bool ssh_rqid_is_event(u16 rqid)
{
	return ssh_rqid_to_event(rqid) < SSH_NUM_EVENTS;
}

static inline int ssh_tc_to_rqid(u8 tc)
{
	return tc;
}

static inline u8 ssh_channel_to_index(u8 channel)
{
	return channel - 1u;
}

static inline bool ssh_channel_is_valid(u8 channel)
{
	return ssh_channel_to_index(channel) < SSH_NUM_CHANNELS;
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
	u16 new = ssh_rqid_next_valid(old);
	u16 ret;

	while (unlikely((ret = cmpxchg(&c->value, old, new)) != old)) {
		old = ret;
		new = ssh_rqid_next_valid(old);
	}

	return old;
}


/* -- Builder functions for SAM-over-SSH messages. -------------------------- */

struct msgbuf {
	u8 *begin;
	u8 *end;
	u8 *ptr;
};

static inline void msgb_init(struct msgbuf *msgb, u8 *ptr, size_t cap)
{
	msgb->begin = ptr;
	msgb->end = ptr + cap;
	msgb->ptr = ptr;
}

static inline size_t msgb_bytes_used(const struct msgbuf *msgb)
{
	return msgb->ptr - msgb->begin;
}

static inline void msgb_push_u16(struct msgbuf *msgb, u16 value)
{
	if (WARN_ON(msgb->ptr + sizeof(u16) > msgb->end))
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

	if (WARN_ON(msgb->ptr + sizeof(*frame) > msgb->end))
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

static inline void msgb_push_cmd(struct msgbuf *msgb, u8 seq, u16 rqid,
				 const struct ssam_request *rqst)
{
	struct ssh_command *cmd;
	const u8 *cmd_begin;
	const u8 type = SSH_FRAME_TYPE_DATA_SEQ;

	// SYN
	msgb_push_syn(msgb);

	// command frame + crc
	msgb_push_frame(msgb, type, sizeof(*cmd) + rqst->length, seq);

	// frame payload: command struct + payload
	if (WARN_ON(msgb->ptr + sizeof(*cmd) > msgb->end))
		return;

	cmd_begin = msgb->ptr;
	cmd = (struct ssh_command *)msgb->ptr;

	cmd->type    = SSH_PLD_TYPE_CMD;
	cmd->tc      = rqst->target_category;
	cmd->chn_out = rqst->channel;
	cmd->chn_in  = 0x00;
	cmd->iid     = rqst->instance_id;
	put_unaligned_le16(rqid, &cmd->rqid);
	cmd->cid     = rqst->command_id;

	msgb->ptr += sizeof(*cmd);

	// command payload
	msgb_push_buf(msgb, rqst->payload, rqst->length);

	// crc for command struct + payload
	msgb_push_crc(msgb, cmd_begin, msgb->ptr - cmd_begin);
}


/* -- Parser functions and utilities for SAM-over-SSH messages. ------------- */

struct sshp_buf {
	u8    *ptr;
	size_t len;
	size_t cap;
};


static inline bool sshp_validate_crc(const struct ssam_span *src, const u8 *crc)
{
	u16 actual = ssh_crc(src->ptr, src->len);
	u16 expected = get_unaligned_le16(crc);

	return actual == expected;
}

static bool sshp_find_syn(const struct ssam_span *src, struct ssam_span *rem)
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

static bool sshp_starts_with_syn(const struct ssam_span *src)
{
	return src->len >= 2 && get_unaligned_le16(src->ptr) == SSH_MSG_SYN;
}

static int sshp_parse_frame(const struct device *dev,
			    const struct ssam_span *source,
			    struct ssh_frame **frame,
			    struct ssam_span *payload,
			    size_t maxlen)
{
	struct ssam_span sf;
	struct ssam_span sp;

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
			      const struct ssam_span *source,
			      struct ssh_command **command,
			      struct ssam_span *command_data)
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
				      struct ssam_span *span)
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
	void (*data_received)(struct ssh_ptl *p, const struct ssam_span *data);
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
		} blocked;
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
 * Causes the packet data to be actively corrupted by overwriting it with
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
	if (!packet->data.ptr || !packet->data.len)
		return false;

	switch (packet->data.ptr[SSH_MSGOFFSET_FRAME(type)]) {
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

static int ssh_ptl_write_buf(struct ssh_ptl *ptl, struct ssh_packet *packet,
			     const unsigned char *buf, size_t count)
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

static void ssh_ptl_tx_inject_invalid_data(struct ssh_packet *packet)
{
	// ignore packets that don't carry any data (i.e. flush)
	if (!packet->data.ptr || !packet->data.len)
		return;

	// only allow sequenced data packets to be modified
	if (packet->data.ptr[SSH_MSGOFFSET_FRAME(type)] != SSH_FRAME_TYPE_DATA_SEQ)
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
	memset(packet->data.ptr, 0xb3, packet->data.len);
}

static void ssh_ptl_rx_inject_invalid_syn(struct ssh_ptl *ptl,
					  struct ssam_span *data)
{
	struct ssam_span frame;

	// check if there actually is something to corrupt
	if (!sshp_find_syn(data, &frame))
		return;

	if (likely(!ssh_ptl_should_corrupt_rx_syn()))
		return;

	trace_ssam_ei_rx_corrupt_syn("data_length", data->len);

	data->ptr[1] = 0xb3;	// set second byte of SYN to "random" value
}

static void ssh_ptl_rx_inject_invalid_data(struct ssh_ptl *ptl,
					   struct ssam_span *frame)
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
						 struct ssam_span *data)
{
}

static inline void ssh_ptl_rx_inject_invalid_data(struct ssh_ptl *ptl,
						  struct ssam_span *frame)
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

void ssh_packet_get(struct ssh_packet *packet)
{
	kref_get(&packet->refcnt);
}
EXPORT_SYMBOL_GPL(ssh_packet_get);

void ssh_packet_put(struct ssh_packet *packet)
{
	kref_put(&packet->refcnt, __ssh_ptl_packet_release);
}
EXPORT_SYMBOL_GPL(ssh_packet_put);

static inline u8 ssh_packet_get_seq(struct ssh_packet *packet)
{
	return packet->data.ptr[SSH_MSGOFFSET_FRAME(seq)];
}


struct ssh_packet_args {
	unsigned long type;
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

	packet->state = args->type & SSH_PACKET_FLAGS_TY_MASK;
	packet->priority = args->priority;
	packet->timestamp = KTIME_MAX;

	packet->data.ptr = NULL;
	packet->data.len = 0;

	packet->ops = args->ops;
}


static struct kmem_cache *ssh_ctrl_packet_cache;

static int __init ssh_ctrl_packet_cache_init(void)
{
	const unsigned int size = sizeof(struct ssh_packet) + SSH_MSG_LEN_CTRL;
	const unsigned int align = __alignof__(struct ssh_packet);
	struct kmem_cache *cache;

	cache = kmem_cache_create("ssam_ctrl_packet", size, align, 0, NULL);
	if (!cache)
		return -ENOMEM;

	ssh_ctrl_packet_cache = cache;
	return 0;
}

static void __exit ssh_ctrl_packet_cache_destroy(void)
{
	kmem_cache_destroy(ssh_ctrl_packet_cache);
	ssh_ctrl_packet_cache = NULL;
}

static int ssh_ctrl_packet_alloc(struct ssh_packet **packet,
				 struct ssam_span *buffer, gfp_t flags)
{
	*packet = kmem_cache_alloc(ssh_ctrl_packet_cache, flags);
	if (!*packet)
		return -ENOMEM;

	buffer->ptr = (u8 *)(*packet + 1);
	buffer->len = SSH_MSG_LEN_CTRL;

	trace_ssam_ctrl_packet_alloc(*packet, buffer->len);
	return 0;
}

static void ssh_ctrl_packet_free(struct ssh_packet *p)
{
	trace_ssam_ctrl_packet_free(p);
	kmem_cache_free(ssh_ctrl_packet_cache, p);
}

static const struct ssh_packet_ops ssh_ptl_ctrl_packet_ops = {
	.complete = NULL,
	.release = ssh_ctrl_packet_free,
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
	if (status && status != -ECANCELED)
		ptl_dbg_cond(ptl, "ptl: packet error: %d\n", status);

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

	if (test_bit(SSH_PACKET_TY_FLUSH_BIT, &packet->state))
		return !atomic_read(&ptl->pending.count);

	// we can alwas process non-blocking packets
	if (!test_bit(SSH_PACKET_TY_BLOCKING_BIT, &packet->state))
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
		if (test_bit(SSH_PACKET_SF_LOCKED_BIT, &p->state))
			continue;

		/*
		 * Packets should be ordered non-blocking/to-be-resent first.
		 * If we cannot process this packet, assume that we can't
		 * process any following packet either and abort.
		 */
		if (!ssh_ptl_tx_can_process(p)) {
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

	if (test_bit(SSH_PACKET_TY_SEQUENCED_BIT, &p->state)) {
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
	if (!test_bit(SSH_PACKET_TY_SEQUENCED_BIT, &packet->state)) {
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
		if (likely(ptl->tx.packet->data.ptr && !drop)) {
			buf = ptl->tx.packet->data.ptr + ptl->tx.offset;
			len = ptl->tx.packet->data.len - ptl->tx.offset;

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


static int ssh_ptl_submit(struct ssh_ptl *ptl, struct ssh_packet *p)
{
	struct ssh_ptl *ptl_old;
	int status;

	trace_ssam_packet_submit(p);

	// validate packet fields
	if (test_bit(SSH_PACKET_TY_FLUSH_BIT, &p->state)) {
		if (p->data.ptr || test_bit(SSH_PACKET_TY_SEQUENCED_BIT, &p->state))
			return -EINVAL;
	} else if (!p->data.ptr) {
		return -EINVAL;
	}

	/*
	 * The ptl reference only gets set on or before the first submission.
	 * After the first submission, it has to be read-only.
	 */
	ptl_old = READ_ONCE(p->ptl);
	if (ptl_old == NULL)
		WRITE_ONCE(p->ptl, ptl);
	else if (ptl_old != ptl)
		return -EALREADY;

	status = ssh_ptl_queue_push(p);
	if (status)
		return status;

	ssh_ptl_tx_wakeup(ptl, !test_bit(SSH_PACKET_TY_BLOCKING_BIT, &p->state));
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


static bool ssh_ptl_rx_retransmit_check(struct ssh_ptl *ptl, u8 seq)
{
	int i;

	// check if SEQ has been seen recently (i.e. packet was re-transmitted)
	for (i = 0; i < ARRAY_SIZE(ptl->rx.blocked.seqs); i++) {
		if (likely(ptl->rx.blocked.seqs[i] != seq))
			continue;

		ptl_dbg(ptl, "ptl: ignoring repeated data packet\n");
		return true;
	}

	// update list of blocked seuence IDs
	ptl->rx.blocked.seqs[ptl->rx.blocked.offset] = seq;
	ptl->rx.blocked.offset = (ptl->rx.blocked.offset + 1)
				  % ARRAY_SIZE(ptl->rx.blocked.seqs);

	return false;
}

static void ssh_ptl_rx_dataframe(struct ssh_ptl *ptl,
				 const struct ssh_frame *frame,
				 const struct ssam_span *payload)
{
	if (ssh_ptl_rx_retransmit_check(ptl, frame->seq))
		return;

	ptl->ops.data_received(ptl, payload);
}

static void ssh_ptl_send_ack(struct ssh_ptl *ptl, u8 seq)
{
	struct ssh_packet_args args;
	struct ssh_packet *packet;
	struct ssam_span buf;
	struct msgbuf msgb;
	int status;

	status = ssh_ctrl_packet_alloc(&packet, &buf, GFP_KERNEL);
	if (status) {
		ptl_err(ptl, "ptl: failed to allocate ACK packet\n");
		return;
	}

	args.type = 0;
	args.priority = SSH_PACKET_PRIORITY(ACK, 0);
	args.ops = &ssh_ptl_ctrl_packet_ops;
	ssh_packet_init(packet, &args);

	msgb_init(&msgb, buf.ptr, buf.len);
	msgb_push_ack(&msgb, seq);
	ssh_packet_set_data(packet, msgb.begin, msgb_bytes_used(&msgb));

	ssh_ptl_submit(ptl, packet);
	ssh_packet_put(packet);
}

static void ssh_ptl_send_nak(struct ssh_ptl *ptl)
{
	struct ssh_packet_args args;
	struct ssh_packet *packet;
	struct ssam_span buf;
	struct msgbuf msgb;
	int status;

	status = ssh_ctrl_packet_alloc(&packet, &buf, GFP_KERNEL);
	if (status) {
		ptl_err(ptl, "ptl: failed to allocate NAK packet\n");
		return;
	}

	args.type = 0;
	args.priority = SSH_PACKET_PRIORITY(NAK, 0);
	args.ops = &ssh_ptl_ctrl_packet_ops;
	ssh_packet_init(packet, &args);

	msgb_init(&msgb, buf.ptr, buf.len);
	msgb_push_nak(&msgb);
	ssh_packet_set_data(packet, msgb.begin, msgb_bytes_used(&msgb));

	ssh_ptl_submit(ptl, packet);
	ssh_packet_put(packet);
}

static size_t ssh_ptl_rx_eval(struct ssh_ptl *ptl, struct ssam_span *source)
{
	struct ssh_frame *frame;
	struct ssam_span payload;
	struct ssam_span aligned;
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
		struct ssam_span span;
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
		return -ESHUTDOWN;

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
	return ptl->serdev ? &ptl->serdev->dev : NULL;
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

	// initialize list of recent/blocked SEQs with invalid sequence IDs
	for (i = 0; i < ARRAY_SIZE(ptl->rx.blocked.seqs); i++)
		ptl->rx.blocked.seqs[i] = 0xFFFF;
	ptl->rx.blocked.offset = 0;

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

#define SSH_RTL_REQUEST_TIMEOUT			ms_to_ktime(3000)
#define SSH_RTL_REQUEST_TIMEOUT_RESOLUTION	ms_to_ktime(max(2000 / HZ, 50))

#define SSH_RTL_MAX_PENDING		3


enum ssh_rtl_state_flags {
	SSH_RTL_SF_SHUTDOWN_BIT,
};

struct ssh_rtl_ops {
	void (*handle_event)(struct ssh_rtl *rtl, const struct ssh_command *cmd,
			     const struct ssam_span *data);
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

static inline struct ssh_rtl *ssh_request_rtl(struct ssh_request *rqst)
{
	struct ssh_ptl *ptl = READ_ONCE(rqst->packet.ptl);
	return likely(ptl) ? to_ssh_rtl(ptl, ptl) : NULL;
}


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


static inline u16 ssh_request_get_rqid(struct ssh_request *rqst)
{
	return get_unaligned_le16(rqst->packet.data.ptr
				  + SSH_MSGOFFSET_COMMAND(rqid));
}

static inline u32 ssh_request_get_rqid_safe(struct ssh_request *rqst)
{
	if (!rqst->packet.data.ptr)
		return -1;

	return ssh_request_get_rqid(rqst);
}


static void ssh_rtl_queue_remove(struct ssh_request *rqst)
{
	struct ssh_rtl *rtl = ssh_request_rtl(rqst);
	bool remove;

	spin_lock(&rtl->queue.lock);

	remove = test_and_clear_bit(SSH_REQUEST_SF_QUEUED_BIT, &rqst->state);
	if (remove)
		list_del(&rqst->node);

	spin_unlock(&rtl->queue.lock);

	if (remove)
		ssh_request_put(rqst);
}

static void ssh_rtl_pending_remove(struct ssh_request *rqst)
{
	struct ssh_rtl *rtl = ssh_request_rtl(rqst);
	bool remove;

	spin_lock(&rtl->pending.lock);

	remove = test_and_clear_bit(SSH_REQUEST_SF_PENDING_BIT, &rqst->state);
	if (remove) {
		atomic_dec(&rtl->pending.count);
		list_del(&rqst->node);
	}

	spin_unlock(&rtl->pending.lock);

	if (remove)
		ssh_request_put(rqst);
}


static void ssh_rtl_complete_with_status(struct ssh_request *rqst, int status)
{
	struct ssh_rtl *rtl = ssh_request_rtl(rqst);

	trace_ssam_request_complete(rqst, status);

	// rtl/ptl may not be set if we're cancelling before submitting
	rtl_dbg_cond(rtl, "rtl: completing request (rqid: 0x%04x,"
		     " status: %d)\n", ssh_request_get_rqid_safe(rqst), status);

	if (status && status != -ECANCELED)
		rtl_dbg_cond(rtl, "rtl: request error: %d\n", status);

	rqst->ops->complete(rqst, NULL, NULL, status);
}

static void ssh_rtl_complete_with_rsp(struct ssh_request *rqst,
				      const struct ssh_command *cmd,
				      const struct ssam_span *data)
{
	struct ssh_rtl *rtl = ssh_request_rtl(rqst);

	trace_ssam_request_complete(rqst, 0);

	rtl_dbg(rtl, "rtl: completing request with response"
		" (rqid: 0x%04x)\n", ssh_request_get_rqid(rqst));

	rqst->ops->complete(rqst, cmd, data, 0);
}


static bool ssh_rtl_tx_can_process(struct ssh_request *rqst)
{
	struct ssh_rtl *rtl = ssh_request_rtl(rqst);

	if (test_bit(SSH_REQUEST_TY_FLUSH_BIT, &rqst->state))
		return !atomic_read(&rtl->pending.count);

	return atomic_read(&rtl->pending.count) < SSH_RTL_MAX_PENDING;
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
	struct ssh_rtl *rtl = ssh_request_rtl(rqst);

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
		if (!test_bit(SSH_PACKET_TY_SEQUENCED_BIT, &rqst->packet.state))
			return -EINVAL;

	// try to set ptl and check if this request has already been submitted
	if (cmpxchg(&rqst->packet.ptl, NULL, &rtl->ptl) != NULL)
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
	struct ssh_rtl *rtl = ssh_request_rtl(rqst);
	ktime_t timestamp = ktime_get_coarse_boottime();
	ktime_t timeout = rtl->rtx_timeout.timeout;

	if (test_bit(SSH_REQUEST_SF_LOCKED_BIT, &rqst->state))
		return;

	WRITE_ONCE(rqst->timestamp, timestamp);
	smp_mb__after_atomic();

	ssh_rtl_timeout_reaper_mod(rtl, timestamp, timestamp + timeout);
}


static void ssh_rtl_complete(struct ssh_rtl *rtl,
			     const struct ssh_command *command,
			     const struct ssam_span *command_data)
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
	struct ssh_rtl *rtl;
	unsigned long state, fixed;
	bool remove;

	/*
	 * Handle unsubmitted request: Try to mark the packet as locked,
	 * expecting the state to be zero (i.e. unsubmitted). Note that, if
	 * setting the state worked, we might still be adding the packet to the
	 * queue in a currently executing submit call. In that case, however,
	 * ptl reference must have been set previously, as locked is checked
	 * after setting ptl. Thus only if we successfully lock this request and
	 * ptl is NULL, we have successfully removed the request.
	 * Otherwise we need to try and grab it from the queue.
	 *
	 * Note that if the CMPXCHG fails, we are guaranteed that ptl has
	 * been set and is non-NULL, as states can only be nonzero after this
	 * has been set. Also note that we need to fetch the static (type) flags
         * to ensure that they don't cause the cmpxchg to fail.
	 */
        fixed = READ_ONCE(r->state) & SSH_REQUEST_FLAGS_TY_MASK;
	state = cmpxchg(&r->state, fixed, SSH_REQUEST_SF_LOCKED_BIT);
	if (!state && !READ_ONCE(r->packet.ptl)) {
		if (test_and_set_bit(SSH_REQUEST_SF_COMPLETED_BIT, &r->state))
			return true;

		ssh_rtl_complete_with_status(r, -ECANCELED);
		return true;
	}

	rtl = ssh_request_rtl(r);
	spin_lock(&rtl->queue.lock);

	/*
	 * Note: 1) Requests cannot be re-submitted. 2) If a request is queued,
	 * it cannot be "transmitting"/"pending" yet. Thus, if we successfully
	 * remove the the request here, we have removed all its occurences in
	 * the system.
	 */

	remove = test_and_clear_bit(SSH_REQUEST_SF_QUEUED_BIT, &r->state);
	if (!remove) {
		spin_unlock(&rtl->queue.lock);
		return false;
	}

	set_bit(SSH_REQUEST_SF_LOCKED_BIT, &r->state);
	list_del(&r->node);

	spin_unlock(&rtl->queue.lock);

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
	 * be added to the system any more. If rtl is zero, the locked
	 * check in ssh_rtl_submit has not been run and any submission,
	 * currently in progress or called later, won't add the packet. Thus we
	 * can directly complete it.
	 */
	if (!ssh_request_rtl(r)) {
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

	// note: rtl may be NULL if request has not been submitted yet
	rtl = ssh_request_rtl(rqst);
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

		ssh_rtl_tx_schedule(ssh_request_rtl(r));
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

	ssh_rtl_tx_schedule(ssh_request_rtl(r));
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
			     const struct ssam_span *data)
{
	trace_ssam_rx_event_received(cmd, data->len);

	rtl_dbg(rtl, "rtl: handling event (rqid: 0x%04x)\n",
		get_unaligned_le16(&cmd->rqid));

	rtl->ops.handle_event(rtl, cmd, data);
}

static void ssh_rtl_rx_command(struct ssh_ptl *p, const struct ssam_span *data)
{
	struct ssh_rtl *rtl = to_ssh_rtl(p, ptl);
	struct device *dev = &p->serdev->dev;
	struct ssh_command *command;
	struct ssam_span command_data;

	if (sshp_parse_command(dev, data, &command, &command_data))
		return;

	if (ssh_rqid_is_event(get_unaligned_le16(&command->rqid)))
		ssh_rtl_rx_event(rtl, command, &command_data);
	else
		ssh_rtl_complete(rtl, command, &command_data);
}

static void ssh_rtl_rx_data(struct ssh_ptl *p, const struct ssam_span *data)
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
			const struct ssh_rtl_ops *ops)
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

	packet_args.type = BIT(SSH_PACKET_TY_BLOCKING_BIT);
	if (!(flags & SSAM_REQUEST_UNSEQUENCED))
		packet_args.type |= BIT(SSH_PACKET_TY_SEQUENCED_BIT);

	packet_args.priority = SSH_PACKET_PRIORITY(DATA, 0);
	packet_args.ops = &ssh_rtl_packet_ops;

	ssh_packet_init(&rqst->packet, &packet_args);
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
					   const struct ssam_span *data,
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
	rqst.base.packet.state |= BIT(SSH_PACKET_TY_FLUSH_BIT);
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
	if (WARN_ON(pending)) {
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
	struct ssam_nf_head head[SSH_NUM_EVENTS];
};


static int ssam_nf_refcount_inc(struct ssam_nf *nf,
				struct ssam_event_registry reg,
				struct ssam_event_id id)
{
	struct ssam_nf_refcount_entry *entry;
	struct ssam_nf_refcount_key key;
	struct rb_node **link = &nf->refcount.rb_node;
	struct rb_node *parent = NULL;
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

static bool ssam_nf_refcount_empty(struct ssam_nf *nf)
{
	return RB_EMPTY_ROOT(&nf->refcount);
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

static int ssam_nf_init(struct ssam_nf *nf)
{
	int i, status;

	for (i = 0; i < SSH_NUM_EVENTS; i++) {
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

	for (i = 0; i < SSH_NUM_EVENTS; i++)
		ssam_nf_head_destroy(&nf->head[i]);

	mutex_destroy(&nf->lock);
}


/* -- Event/async request completion system. -------------------------------- */

#define SSAM_CPLT_WQ_NAME	"ssam_cpltq"


struct ssam_cplt;
struct ssam_event_item;

struct ssam_event_item_ops {
	void (*free)(struct ssam_event_item *);
};

struct ssam_event_item {
	struct list_head node;
	u16 rqid;

	struct ssam_event_item_ops ops;
	struct ssam_event event;	// must be last
};

struct ssam_event_queue {
	struct ssam_cplt *cplt;

	spinlock_t lock;
	struct list_head head;
	struct work_struct work;
};

struct ssam_event_channel {
	struct ssam_event_queue queue[SSH_NUM_EVENTS];
};

struct ssam_cplt {
	struct device *dev;
	struct workqueue_struct *wq;

	struct {
		struct ssam_event_channel channel[SSH_NUM_CHANNELS];
		struct ssam_nf notif;
	} event;
};


/**
 * Maximum payload length for cached `ssam_event_item`s.
 *
 * This length has been chosen to be accomodate standard touchpad and keyboard
 * input events. Events with larger payloads will be allocated separately.
 */
#define SSAM_EVENT_ITEM_CACHE_PAYLOAD_LEN	32

static struct kmem_cache *ssam_event_item_cache;

static int ssam_event_item_cache_init(void)
{
	const unsigned int size = sizeof(struct ssam_event_item)
				  + SSAM_EVENT_ITEM_CACHE_PAYLOAD_LEN;
	const unsigned int align = __alignof__(struct ssam_event_item);
	struct kmem_cache *cache;

	cache = kmem_cache_create("ssam_event_item", size, align, 0, NULL);
	if (!cache)
		return -ENOMEM;

	ssam_event_item_cache = cache;
	return 0;
}

static void ssam_event_item_cache_destroy(void)
{
	kmem_cache_destroy(ssam_event_item_cache);
	ssam_event_item_cache = NULL;
}

static void __ssam_event_item_free_cached(struct ssam_event_item *item)
{
	kmem_cache_free(ssam_event_item_cache, item);
}

static void __ssam_event_item_free_generic(struct ssam_event_item *item)
{
	kfree(item);
}

static inline void ssam_event_item_free(struct ssam_event_item *item)
{
	trace_ssam_event_item_free(item);
	item->ops.free(item);
}

static struct ssam_event_item *ssam_event_item_alloc(size_t len, gfp_t flags)
{
	struct ssam_event_item *item;

	if (len <= SSAM_EVENT_ITEM_CACHE_PAYLOAD_LEN) {
		item = kmem_cache_alloc(ssam_event_item_cache, GFP_KERNEL);
		if (!item)
			return NULL;

		item->ops.free = __ssam_event_item_free_cached;
	} else {
		const size_t n = sizeof(struct ssam_event_item) + len;
		item = kzalloc(n, GFP_KERNEL);
		if (!item)
			return NULL;

		item->ops.free = __ssam_event_item_free_generic;
	}

	item->event.length = len;

	trace_ssam_event_item_alloc(item, len);
	return item;
}


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
		ssam_event_item_free(item);
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
	/*
	 * Note: destroy_workqueue ensures that all currently queued work will
	 * be fully completed and the workqueue drained. This means that this
	 * call will inherently also free any queued ssam_event_items, thus we
	 * don't have to take care of that here explicitly.
	 */
	destroy_workqueue(cplt->wq);
	ssam_nf_destroy(&cplt->event.notif);
}


/* -- Main SSAM device structures. ------------------------------------------ */

enum ssam_controller_state {
	SSAM_CONTROLLER_UNINITIALIZED,
	SSAM_CONTROLLER_INITIALIZED,
	SSAM_CONTROLLER_STARTED,
	SSAM_CONTROLLER_STOPPED,
	SSAM_CONTROLLER_SUSPENDED,
};

struct ssam_device_caps {
	u32 notif_display:1;
	u32 notif_d0exit:1;
};

struct ssam_controller {
	enum ssam_controller_state state;

	struct ssh_rtl rtl;
	struct ssam_cplt cplt;

	struct {
		struct ssh_seq_counter seq;
		struct ssh_rqid_counter rqid;
	} counter;

	struct {
		int num;
		bool wakeup_enabled;
	} irq;

	struct ssam_device_caps caps;
};


#define ssam_dbg(ctrl, fmt, ...)  rtl_dbg(&(ctrl)->rtl, fmt, ##__VA_ARGS__)
#define ssam_info(ctrl, fmt, ...) rtl_info(&(ctrl)->rtl, fmt, ##__VA_ARGS__)
#define ssam_warn(ctrl, fmt, ...) rtl_warn(&(ctrl)->rtl, fmt, ##__VA_ARGS__)
#define ssam_err(ctrl, fmt, ...)  rtl_err(&(ctrl)->rtl, fmt, ##__VA_ARGS__)

#define to_ssam_controller(ptr, member) \
	container_of(ptr, struct ssam_controller, member)

struct device *ssam_controller_device(struct ssam_controller *c)
{
	return ssh_rtl_get_device(&c->rtl);
}
EXPORT_SYMBOL_GPL(ssam_controller_device);


static void ssam_handle_event(struct ssh_rtl *rtl,
			      const struct ssh_command *cmd,
			      const struct ssam_span *data)
{
	struct ssam_controller *ctrl = to_ssam_controller(rtl, rtl);
	struct ssam_event_item *item;

	item = ssam_event_item_alloc(data->len, GFP_KERNEL);
	if (!item)
		return;

	item->rqid = get_unaligned_le16(&cmd->rqid);
	item->event.target_category = cmd->tc;
	item->event.command_id = cmd->cid;
	item->event.instance_id = cmd->iid;
	item->event.channel = cmd->chn_in;
	memcpy(&item->event.data[0], data->ptr, data->len);

	ssam_cplt_submit_event(&ctrl->cplt, item);
}

static const struct ssh_rtl_ops ssam_rtl_ops = {
	.handle_event = ssam_handle_event,
};


static bool ssam_notifier_empty(struct ssam_controller *ctrl);
static void ssam_notifier_unregister_all(struct ssam_controller *ctrl);


#define SSAM_SSH_DSM_REVISION	0
#define SSAM_SSH_DSM_NOTIF_D0	8
static const guid_t SSAM_SSH_DSM_UUID = GUID_INIT(0xd5e383e1, 0xd892, 0x4a76,
		0x89, 0xfc, 0xf6, 0xaa, 0xae, 0x7e, 0xd5, 0xb5);

static int ssam_device_caps_load_from_acpi(acpi_handle handle,
					   struct ssam_device_caps *caps)
{
	union acpi_object *obj;
	u64 funcs = 0;
	int i;

	// set defaults
	caps->notif_display = true;
	caps->notif_d0exit = false;

	if (!acpi_has_method(handle, "_DSM"))
		return 0;

	// get function availability bitfield
	obj = acpi_evaluate_dsm_typed(handle, &SSAM_SSH_DSM_UUID, 0, 0, NULL,
			ACPI_TYPE_BUFFER);
	if (!obj)
		return -EFAULT;

	for (i = 0; i < obj->buffer.length && i < 8; i++)
		funcs |= (((u64)obj->buffer.pointer[i]) << (i * 8));

	ACPI_FREE(obj);

	// D0 exit/entry notification
	if (funcs & BIT(SSAM_SSH_DSM_NOTIF_D0)) {
		obj = acpi_evaluate_dsm_typed(handle, &SSAM_SSH_DSM_UUID,
				SSAM_SSH_DSM_REVISION, SSAM_SSH_DSM_NOTIF_D0,
				NULL, ACPI_TYPE_INTEGER);
		if (!obj)
			return -EFAULT;

		caps->notif_d0exit = !!obj->integer.value;
		ACPI_FREE(obj);
	}

	return 0;
}

static int ssam_controller_init(struct ssam_controller *ctrl,
				struct serdev_device *serdev)
{
	acpi_handle handle = ACPI_HANDLE(&serdev->dev);
	int status;

	if (smp_load_acquire(&ctrl->state) != SSAM_CONTROLLER_UNINITIALIZED) {
		dev_err(&serdev->dev, "embedded controller already initialized\n");
		return -EBUSY;
	}

	status = ssam_device_caps_load_from_acpi(handle, &ctrl->caps);
	if (status)
		return status;

	dev_dbg(&serdev->dev, "device capabilities:\n");
	dev_dbg(&serdev->dev, "  notif_display: %u\n", ctrl->caps.notif_display);
	dev_dbg(&serdev->dev, "  notif_d0exit:  %u\n", ctrl->caps.notif_d0exit);

	ssh_seq_reset(&ctrl->counter.seq);
	ssh_rqid_reset(&ctrl->counter.rqid);

	// initialize event/request completion system
	status = ssam_cplt_init(&ctrl->cplt, &serdev->dev);
	if (status)
		return status;

	// initialize request and packet transmission layers
	status = ssh_rtl_init(&ctrl->rtl, serdev, &ssam_rtl_ops);
	if (status) {
		ssam_cplt_destroy(&ctrl->cplt);
		return status;
	}

	// update state
	smp_store_release(&ctrl->state, SSAM_CONTROLLER_INITIALIZED);
	return 0;
}

static int ssam_controller_start(struct ssam_controller *ctrl)
{
	int status;

	if (smp_load_acquire(&ctrl->state) != SSAM_CONTROLLER_INITIALIZED)
		return -EINVAL;

	status = ssh_rtl_tx_start(&ctrl->rtl);
	if (status)
		return status;

	status = ssh_rtl_rx_start(&ctrl->rtl);
	if (status) {
		ssh_rtl_tx_flush(&ctrl->rtl);
		return status;
	}

	smp_store_release(&ctrl->state, SSAM_CONTROLLER_STARTED);
	return 0;
}

static void ssam_controller_shutdown(struct ssam_controller *ctrl)
{
	enum ssam_controller_state s = smp_load_acquire(&ctrl->state);
	int status;

	if (s == SSAM_CONTROLLER_UNINITIALIZED || s == SSAM_CONTROLLER_STOPPED)
		return;

	// try to flush pending events and requests while everything still works
	status = ssh_rtl_flush(&ctrl->rtl, msecs_to_jiffies(5000));
	if (status) {
		ssam_err(ctrl, "failed to flush request transmission layer: %d\n",
			 status);
	}

	// try to flush out all currently completing requests and events
	ssam_cplt_flush(&ctrl->cplt);

	/*
	 * We expect all notifiers to have been removed by the respective client
	 * driver that set them up at this point. If this warning occurs, some
	 * client driver has not done that...
	 */
	WARN_ON(!ssam_notifier_empty(ctrl));

	/*
	 * Nevertheless, we should still take care of drivers that don't behave
	 * well. Thus disable all enabled events, unregister all notifiers.
	 */
	ssam_notifier_unregister_all(ctrl);

	// cancel rem. requests, ensure no new ones can be queued, stop threads
	ssh_rtl_tx_flush(&ctrl->rtl);
	ssh_rtl_shutdown(&ctrl->rtl);

	smp_store_release(&ctrl->state, SSAM_CONTROLLER_STOPPED);
}

static void ssam_controller_destroy(struct ssam_controller *ctrl)
{
	if (smp_load_acquire(&ctrl->state) == SSAM_CONTROLLER_UNINITIALIZED)
		return;

	/*
	 * Note: New events could still have been received after the previous
	 * flush in ssam_controller_shutdown, before the request transport layer
	 * has been shut down. At this point, after the shutdown, we can be sure
	 * that no new events will be queued. The call to ssam_cplt_destroy will
	 * ensure that those remaining are being completed and freed.
	 */

	// actually free resources
	ssam_cplt_destroy(&ctrl->cplt);
	ssh_rtl_destroy(&ctrl->rtl);

	smp_store_release(&ctrl->state, SSAM_CONTROLLER_UNINITIALIZED);
}

static int ssam_controller_suspend(struct ssam_controller *ctrl)
{
	if (smp_load_acquire(&ctrl->state) != SSAM_CONTROLLER_STARTED)
		return -EINVAL;

	ssam_dbg(ctrl, "pm: suspending controller\n");
	smp_store_release(&ctrl->state, SSAM_CONTROLLER_SUSPENDED);
	return 0;
}

static int ssam_controller_resume(struct ssam_controller *ctrl)
{
	if (smp_load_acquire(&ctrl->state) != SSAM_CONTROLLER_SUSPENDED)
		return -EINVAL;

	ssam_dbg(ctrl, "pm: resuming controller\n");
	smp_store_release(&ctrl->state, SSAM_CONTROLLER_STARTED);
	return 0;
}


static inline
int ssam_controller_receive_buf(struct ssam_controller *ctrl,
				const unsigned char *buf, size_t n)
{
	return ssh_ptl_rx_rcvbuf(&ctrl->rtl.ptl, buf, n);
}

static inline void ssam_controller_write_wakeup(struct ssam_controller *ctrl)
{
	ssh_ptl_tx_wakeup(&ctrl->rtl.ptl, true);
}


/* -- Top-level request interface ------------------------------------------- */

ssize_t ssam_request_write_data(struct ssam_span *buf,
				struct ssam_controller *ctrl,
				struct ssam_request *spec)
{
	struct msgbuf msgb;
	u16 rqid;
	u8 seq;

	if (spec->length > SSH_COMMAND_MAX_PAYLOAD_SIZE)
		return -EINVAL;

	msgb_init(&msgb, buf->ptr, buf->len);
	seq = ssh_seq_next(&ctrl->counter.seq);
	rqid = ssh_rqid_next(&ctrl->counter.rqid);
	msgb_push_cmd(&msgb, seq, rqid, spec);

	return msgb_bytes_used(&msgb);
}
EXPORT_SYMBOL_GPL(ssam_request_write_data);


static void ssam_request_sync_complete(struct ssh_request *rqst,
				       const struct ssh_command *cmd,
				       const struct ssam_span *data, int status)
{
	struct ssh_rtl *rtl = ssh_request_rtl(rqst);
	struct ssam_request_sync *r;

	r = container_of(rqst, struct ssam_request_sync, base);
	r->status = status;

        if (r->resp)
	        r->resp->length = 0;

	if (status) {
		rtl_dbg_cond(rtl, "rsp: request failed: %d\n", status);
		return;
	}

	if (!data)	// handle requests without a response
		return;

	if (!r->resp || !r->resp->pointer) {
                if (data->len) {
		        rtl_warn(rtl, "rsp: no response buffer provided, "
                                 "dropping data\n");
                }
                return;
        }

	if (data->len > r->resp->capacity) {
		rtl_err(rtl, "rsp: response buffer too small, "
			"capacity: %zu bytes, got: %zu bytes\n",
			r->resp->capacity, data->len);
		r->status = -ENOSPC;
		return;
	}

	r->resp->length = data->len;
	memcpy(r->resp->pointer, data->ptr, data->len);
}

static void ssam_request_sync_release(struct ssh_request *rqst)
{
	complete_all(&container_of(rqst, struct ssam_request_sync, base)->comp);
}

static const struct ssh_request_ops ssam_request_sync_ops = {
	.release = ssam_request_sync_release,
	.complete = ssam_request_sync_complete,
};


int ssam_request_sync_alloc(size_t payload_len, gfp_t flags,
			    struct ssam_request_sync **rqst,
			    struct ssam_span *buffer)
{
	size_t msglen = SSH_COMMAND_MESSAGE_LENGTH(payload_len);

	*rqst = kzalloc(sizeof(struct ssam_request_sync) + msglen, flags);
	if (!*rqst)
		return -ENOMEM;

	buffer->ptr = (u8 *)(*rqst + 1);
	buffer->len = msglen;

	return 0;
}
EXPORT_SYMBOL_GPL(ssam_request_sync_alloc);

void ssam_request_sync_init(struct ssam_request_sync *rqst,
			    enum ssam_request_flags flags)
{
	ssh_request_init(&rqst->base, flags, &ssam_request_sync_ops);
	init_completion(&rqst->comp);
	rqst->resp = NULL;
	rqst->status = 0;
}
EXPORT_SYMBOL_GPL(ssam_request_sync_init);

int ssam_request_sync_submit(struct ssam_controller *ctrl,
			     struct ssam_request_sync *rqst)
{
	enum ssam_controller_state state = smp_load_acquire(&ctrl->state);
	int status;

	if (state == SSAM_CONTROLLER_SUSPENDED) {
		ssam_warn(ctrl, "rqst: embedded controller is suspended\n");
		ssh_request_put(&rqst->base);
		return -EPERM;
	}

	if (state != SSAM_CONTROLLER_STARTED) {
		ssam_warn(ctrl, "rqst: embedded controller is uninitialized\n");
		ssh_request_put(&rqst->base);
		return -ENXIO;
	}

	status = ssh_rtl_submit(&ctrl->rtl, &rqst->base);
	ssh_request_put(&rqst->base);

	return status;
}
EXPORT_SYMBOL_GPL(ssam_request_sync_submit);

int ssam_request_sync(struct ssam_controller *ctrl, struct ssam_request *spec,
		      struct ssam_response *rsp)
{
	struct ssam_request_sync *rqst;
	struct ssam_span buf;
	size_t len;
	int status;

	// prevent overflow, allows us to skip checks later on
	if (spec->length > SSH_COMMAND_MAX_PAYLOAD_SIZE) {
		ssam_err(ctrl, "rqst: request payload too large\n");
		return -EINVAL;
	}

	status = ssam_request_sync_alloc(spec->length, GFP_KERNEL, &rqst, &buf);
	if (status)
		return status;

	ssam_request_sync_init(rqst, spec->flags);
	ssam_request_sync_set_resp(rqst, rsp);

	len = ssam_request_write_data(&buf, ctrl, spec);
	ssam_request_sync_set_data(rqst, buf.ptr, len);

	status = ssam_request_sync_submit(ctrl, rqst);
	if (!status)
		status = ssam_request_sync_wait(rqst);

	kfree(rqst);
	return status;
}
EXPORT_SYMBOL_GPL(ssam_request_sync);

int ssam_request_sync_with_buffer(struct ssam_controller *ctrl,
				  struct ssam_request *spec,
				  struct ssam_response *rsp,
				  struct ssam_span *buf)
{
	struct ssam_request_sync rqst;
	size_t len;
	int status;

	// prevent overflow, allows us to skip checks later on
	if (spec->length > SSH_COMMAND_MAX_PAYLOAD_SIZE) {
		ssam_err(ctrl, "rqst: request payload too large\n");
		return -EINVAL;
	}

	ssam_request_sync_init(&rqst, spec->flags);
	ssam_request_sync_set_resp(&rqst, rsp);

	len = ssam_request_write_data(buf, ctrl, spec);
	ssam_request_sync_set_data(&rqst, buf->ptr, len);

	status = ssam_request_sync_submit(ctrl, &rqst);
	if (!status)
		status = ssam_request_sync_wait(&rqst);

	return status;
}
EXPORT_SYMBOL_GPL(ssam_request_sync_with_buffer);


/* -- Internal SAM requests. ------------------------------------------------ */

static SSAM_DEFINE_SYNC_REQUEST_R(ssam_ssh_get_firmware_version, __le32, {
	.target_category = SSAM_SSH_TC_SAM,
	.command_id      = 0x13,
	.instance_id     = 0x00,
	.channel         = 0x01,
});

static SSAM_DEFINE_SYNC_REQUEST_R(ssam_ssh_notif_display_off, u8, {
	.target_category = SSAM_SSH_TC_SAM,
	.command_id      = 0x15,
	.instance_id     = 0x00,
	.channel         = 0x01,
});

static SSAM_DEFINE_SYNC_REQUEST_R(ssam_ssh_notif_display_on, u8, {
	.target_category = SSAM_SSH_TC_SAM,
	.command_id      = 0x16,
	.instance_id     = 0x00,
	.channel         = 0x01,
});

static SSAM_DEFINE_SYNC_REQUEST_R(ssam_ssh_notif_d0_exit, u8, {
	.target_category = SSAM_SSH_TC_SAM,
	.command_id      = 0x33,
	.instance_id     = 0x00,
	.channel         = 0x01,
});

static SSAM_DEFINE_SYNC_REQUEST_R(ssam_ssh_notif_d0_entry, u8, {
	.target_category = SSAM_SSH_TC_SAM,
	.command_id      = 0x34,
	.instance_id     = 0x00,
	.channel         = 0x01,
});

static int ssam_ssh_event_enable(struct ssam_controller *ctrl,
				 struct ssam_event_registry reg,
				 struct ssam_event_id id, u8 flags)
{
	struct ssh_notification_params params;
	struct ssam_request rqst;
	struct ssam_response result;
	int status;

	u16 rqid = ssh_tc_to_rqid(id.target_category);
	u8 buf[1] = { 0x00 };

	// only allow RQIDs that lie within event spectrum
	if (!ssh_rqid_is_event(rqid))
		return -EINVAL;

	params.target_category = id.target_category;
	params.instance_id = id.instance;
	params.flags = flags;
	put_unaligned_le16(rqid, &params.request_id);

	rqst.target_category = reg.target_category;
	rqst.command_id = reg.cid_enable;
	rqst.instance_id = 0x00;
	rqst.channel = reg.channel;
	rqst.flags = SSAM_REQUEST_HAS_RESPONSE;
	rqst.length = sizeof(params);
	rqst.payload = (u8 *)&params;

	result.capacity = ARRAY_SIZE(buf);
	result.length = 0;
	result.pointer = buf;

	status = ssam_request_sync_onstack(ctrl, &rqst, &result, sizeof(params));
	if (status) {
		ssam_err(ctrl, "failed to enable event source "
			 "(tc: 0x%02x, iid: 0x%02x, reg: 0x%02x)\n",
			 id.target_category, id.instance, reg.target_category);
	}

	if (buf[0] != 0x00) {
		ssam_warn(ctrl, "unexpected result while enabling event source: "
			  "0x%02x (tc: 0x%02x, iid: 0x%02x, reg: 0x%02x)\n",
			  buf[0], id.target_category, id.instance,
			  reg.target_category);
	}

	return status;

}

static int ssam_ssh_event_disable(struct ssam_controller *ctrl,
				  struct ssam_event_registry reg,
				  struct ssam_event_id id, u8 flags)
{
	struct ssh_notification_params params;
	struct ssam_request rqst;
	struct ssam_response result;
	int status;

	u16 rqid = ssh_tc_to_rqid(id.target_category);
	u8 buf[1] = { 0x00 };

	// only allow RQIDs that lie within event spectrum
	if (!ssh_rqid_is_event(rqid))
		return -EINVAL;

	params.target_category = id.target_category;
	params.instance_id = id.instance;
	params.flags = flags;
	put_unaligned_le16(rqid, &params.request_id);

	rqst.target_category = reg.target_category;
	rqst.command_id = reg.cid_disable;
	rqst.instance_id = 0x00;
	rqst.channel = reg.channel;
	rqst.flags = SSAM_REQUEST_HAS_RESPONSE;
	rqst.length = sizeof(params);
	rqst.payload = (u8 *)&params;

	result.capacity = ARRAY_SIZE(buf);
	result.length = 0;
	result.pointer = buf;

	status = ssam_request_sync_onstack(ctrl, &rqst, &result, sizeof(params));
	if (status) {
		ssam_err(ctrl, "failed to disable event source "
			 "(tc: 0x%02x, iid: 0x%02x, reg: 0x%02x)\n",
			 id.target_category, id.instance, reg.target_category);
	}

	if (buf[0] != 0x00) {
		ssam_warn(ctrl, "unexpected result while disabling event source: "
			  "0x%02x (tc: 0x%02x, iid: 0x%02x, reg: 0x%02x)\n",
			  buf[0], id.target_category, id.instance,
			  reg.target_category);
	}

	return status;
}


/* -- Wrappers for internal SAM requests. ----------------------------------- */

static int ssam_log_firmware_version(struct ssam_controller *ctrl)
{
	__le32 __version;
	u32 version, a, b, c;
	int status;

	status = ssam_ssh_get_firmware_version(ctrl, &__version);
	if (status)
		return status;

	version = le32_to_cpu(__version);
	a = (version >> 24) & 0xff;
	b = ((version >> 8) & 0xffff);
	c = version & 0xff;

	ssam_info(ctrl, "SAM controller version: %u.%u.%u\n", a, b, c);
	return 0;
}

static int ssam_ctrl_notif_display_off(struct ssam_controller *ctrl)
{
	int status;
	u8 response;

	if (!ctrl->caps.notif_display)
		return 0;

	ssam_dbg(ctrl, "pm: notifying display off\n");

	status = ssam_ssh_notif_display_off(ctrl, &response);
	if (status)
		return status;

	if (response != 0) {
		ssam_err(ctrl, "unexpected response from display-off notification: "
			 "0x%02x\n", response);
		return -EIO;
	}

	return 0;
}

static int ssam_ctrl_notif_display_on(struct ssam_controller *ctrl)
{
	int status;
	u8 response;

	if (!ctrl->caps.notif_display)
		return 0;

	ssam_dbg(ctrl, "pm: notifying display on\n");

	status = ssam_ssh_notif_display_on(ctrl, &response);
	if (status)
		return status;

	if (response != 0) {
		ssam_err(ctrl, "unexpected response from display-on notification: "
			 "0x%02x\n", response);
		return -EIO;
	}

	return 0;
}

static int ssam_ctrl_notif_d0_exit(struct ssam_controller *ctrl)
{
	int status;
	u8 response;

	if (!ctrl->caps.notif_d0exit)
		return 0;

	ssam_dbg(ctrl, "pm: notifying D0 exit\n");

	status = ssam_ssh_notif_d0_exit(ctrl, &response);
	if (status)
		return status;

	if (response != 0) {
		ssam_err(ctrl, "unexpected response from D0-exit notification: "
			 "0x%02x\n", response);
		return -EIO;
	}

	return 0;
}

static int ssam_ctrl_notif_d0_entry(struct ssam_controller *ctrl)
{
	int status;
	u8 response;

	if (!ctrl->caps.notif_d0exit)
		return 0;

	ssam_dbg(ctrl, "pm: notifying D0 entry\n");

	status = ssam_ssh_notif_d0_entry(ctrl, &response);
	if (status)
		return status;

	if (response != 0) {
		ssam_err(ctrl, "unexpected response from D0-entry notification: "
			 "0x%02x\n", response);
		return -EIO;
	}

	return 0;
}


/* -- Top-level event registry interface. ----------------------------------- */

int ssam_notifier_register(struct ssam_controller *ctrl,
			   struct ssam_event_notifier *n)
{
	u16 rqid = ssh_tc_to_rqid(n->event.id.target_category);
	struct ssam_nf_head *nf_head;
	struct ssam_nf *nf;
	int rc, status;

	if (!ssh_rqid_is_event(rqid))
		return -EINVAL;

	nf = &ctrl->cplt.event.notif;
	nf_head = &nf->head[ssh_rqid_to_event(rqid)];

	mutex_lock(&nf->lock);

	if (smp_load_acquire(&ctrl->state) != SSAM_CONTROLLER_STARTED) {
		mutex_unlock(&nf->lock);
		return -ENXIO;
	}

	rc = ssam_nf_refcount_inc(nf, n->event.reg, n->event.id);
	if (rc < 0) {
		mutex_unlock(&nf->lock);
		return rc;
	}

	ssam_dbg(ctrl, "enabling event (reg: 0x%02x, tc: 0x%02x, iid: 0x%02x, "
		 "rc: %d)\n", n->event.reg.target_category,
		 n->event.id.target_category, n->event.id.instance, rc);

	status = __ssam_nfblk_insert(nf_head, &n->base);
	if (status) {
		ssam_nf_refcount_dec(nf, n->event.reg, n->event.id);
		mutex_unlock(&nf->lock);
		return status;
	}

	if (rc == 1) {
		status = ssam_ssh_event_enable(ctrl, n->event.reg, n->event.id,
					       n->event.flags);
		if (status) {
			__ssam_nfblk_remove(nf_head, &n->base);
			ssam_nf_refcount_dec(nf, n->event.reg, n->event.id);
			mutex_unlock(&nf->lock);
			synchronize_srcu(&nf_head->srcu);
			return status;
		}
	}

	mutex_unlock(&nf->lock);
	return 0;

}
EXPORT_SYMBOL_GPL(ssam_notifier_register);

int ssam_notifier_unregister(struct ssam_controller *ctrl,
			     struct ssam_event_notifier *n)
{
	u16 rqid = ssh_tc_to_rqid(n->event.id.target_category);
	struct ssam_nf_head *nf_head;
	struct ssam_nf *nf;
	int rc, status = 0;

	if (!ssh_rqid_is_event(rqid))
		return -EINVAL;

	nf = &ctrl->cplt.event.notif;
	nf_head = &nf->head[ssh_rqid_to_event(rqid)];

	mutex_lock(&nf->lock);

	if (smp_load_acquire(&ctrl->state) != SSAM_CONTROLLER_STARTED) {
		mutex_unlock(&nf->lock);
		return -ENXIO;
	}

	rc = ssam_nf_refcount_dec(nf, n->event.reg, n->event.id);
	if (rc < 0) {
		mutex_unlock(&nf->lock);
		return rc;
	}

	ssam_dbg(ctrl, "disabling event (reg: 0x%02x, tc: 0x%02x, iid: 0x%02x, "
		 "rc: %d)\n", n->event.reg.target_category,
		 n->event.id.target_category, n->event.id.instance, rc);

	if (rc == 0) {
		status = ssam_ssh_event_disable(ctrl, n->event.reg, n->event.id,
						n->event.flags);
	}

	__ssam_nfblk_remove(nf_head, &n->base);
	mutex_unlock(&nf->lock);
	synchronize_srcu(&nf_head->srcu);

	return status;
}
EXPORT_SYMBOL_GPL(ssam_notifier_unregister);

static bool ssam_notifier_empty(struct ssam_controller *ctrl)
{
	struct ssam_nf *nf = &ctrl->cplt.event.notif;
	bool result;

	mutex_lock(&nf->lock);
	result = ssam_nf_refcount_empty(nf);
	mutex_unlock(&nf->lock);

	return result;
}

static void ssam_notifier_unregister_all(struct ssam_controller *ctrl)
{
	struct ssam_nf *nf = &ctrl->cplt.event.notif;
	struct ssam_nf_refcount_entry *pos, *n;

	mutex_lock(&nf->lock);
	rbtree_postorder_for_each_entry_safe(pos, n, &nf->refcount, node) {
		// ignore errors, will get logged in call
		ssam_ssh_event_disable(ctrl, pos->key.reg, pos->key.id, 0);
		kfree(pos);
	}
	nf->refcount = RB_ROOT;
	mutex_unlock(&nf->lock);
}


/* -- Wakeup IRQ. ----------------------------------------------------------- */

static const struct acpi_gpio_params gpio_ssam_wakeup_int = { 0, 0, false };
static const struct acpi_gpio_params gpio_ssam_wakeup     = { 1, 0, false };

static const struct acpi_gpio_mapping ssam_acpi_gpios[] = {
	{ "ssam_wakeup-int-gpio", &gpio_ssam_wakeup_int, 1 },
	{ "ssam_wakeup-gpio",     &gpio_ssam_wakeup,     1 },
	{ },
};

static irqreturn_t ssam_irq_handle(int irq, void *dev_id)
{
	struct ssam_controller *ctrl = dev_id;

	ssam_dbg(ctrl, "pm: wake irq triggered\n");

	// Note: Proper wakeup detection is currently unimplemented.
	//       When the EC is in display-off or any other non-D0 state, it
	//       does not send events/notifications to the host. Instead it
	//       signals that there are events available via the wakeup IRQ.
	//       This driver is responsible for calling back to the EC to
	//       release these events one-by-one.
	//
	//       This IRQ should not cause a full system resume by its own.
	//       Instead, events should be handled by their respective subsystem
	//       drivers, which in turn should signal whether a full system
	//       resume should be performed.
	//
	// TODO: Send GPIO callback command repeatedly to EC until callback
	//       returns 0x00. Return flag of callback is "has more events".
	//       Each time the command is sent, one event is "released". Once
	//       all events have been released (return = 0x00), the GPIO is
	//       re-armed. Detect wakeup events during this process, go back to
	//       sleep if no wakeup event has been received.

	return IRQ_HANDLED;
}

static int ssam_irq_setup(struct ssam_controller *ctrl)
{
	struct device *dev = ssam_controller_device(ctrl);
	struct gpio_desc *gpiod;
	int irq;
	int status;

	/*
	 * The actual GPIO interrupt is declared in ACPI as TRIGGER_HIGH.
	 * However, the GPIO line only gets reset by sending the GPIO callback
	 * command to SAM (or alternatively the display-on notification). As
	 * proper handling for this interrupt is not implemented yet, leaving
	 * the IRQ at TRIGGER_HIGH would cause an IRQ storm (as the callback
	 * never gets sent and thus the line line never gets reset). To avoid
	 * this, mark the IRQ as TRIGGER_RISING for now, only creating a single
	 * interrupt, and let the SAM resume callback during the controller
	 * resume process clear it.
	 */
	const int irqf = IRQF_SHARED | IRQF_ONESHOT | IRQF_TRIGGER_RISING;

	gpiod = gpiod_get(dev, "ssam_wakeup-int", GPIOD_ASIS);
	if (IS_ERR(gpiod))
		return PTR_ERR(gpiod);

	irq = gpiod_to_irq(gpiod);
	gpiod_put(gpiod);

	if (irq < 0)
		return irq;

	status = request_threaded_irq(irq, NULL, ssam_irq_handle, irqf,
				      "surface_sam_wakeup", ctrl);
	if (status)
		return status;

	ctrl->irq.num = irq;
	return 0;
}

static void ssam_irq_free(struct ssam_controller *ctrl)
{
	free_irq(ctrl->irq.num, ctrl);
	ctrl->irq.num = -1;
}


/* -- Glue layer (serdev_device -> ssam_controller). ------------------------ */

static int ssam_receive_buf(struct serdev_device *dev, const unsigned char *buf,
			    size_t n)
{
	struct ssam_controller *ctrl = serdev_device_get_drvdata(dev);
	return ssam_controller_receive_buf(ctrl, buf, n);
}

static void ssam_write_wakeup(struct serdev_device *dev)
{
	struct ssam_controller *ctrl = serdev_device_get_drvdata(dev);
	ssam_controller_write_wakeup(ctrl);
}

static const struct serdev_device_ops ssam_serdev_ops = {
	.receive_buf = ssam_receive_buf,
	.write_wakeup = ssam_write_wakeup,
};


/* -- ACPI based device setup. ---------------------------------------------- */

static acpi_status ssam_serdev_setup_via_acpi_crs(struct acpi_resource *rsc,
						  void *ctx)
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
	if (uart->flow_control & (~((u8) ACPI_UART_FLOW_CONTROL_HW))) {
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

static acpi_status ssam_serdev_setup_via_acpi(acpi_handle handle,
					      struct serdev_device *serdev)
{
	return acpi_walk_resources(handle, METHOD_NAME__CRS,
				   ssam_serdev_setup_via_acpi_crs, serdev);
}


/* -- Power management. ----------------------------------------------------- */

static void surface_sam_ssh_shutdown(struct device *dev)
{
	struct ssam_controller *c = dev_get_drvdata(dev);
	int status;

	/*
	 * Try to signal display-off and D0-exit, ignore any errors.
	 *
	 * Note: It has not been established yet if this is actually
	 * necessary/useful for shutdown.
	 */

	status = ssam_ctrl_notif_display_off(c);
	if (status)
		ssam_err(c, "pm: display-off notification failed: %d\n", status);

	status = ssam_ctrl_notif_d0_exit(c);
	if (status)
		ssam_err(c, "pm: D0-exit notification failed: %d\n", status);
}

static int surface_sam_ssh_suspend(struct device *dev)
{
	struct ssam_controller *c = dev_get_drvdata(dev);
	int status;

	/*
	 * Try to signal display-off and D0-exit, enable IRQ wakeup if
	 * specified. Abort on error.
	 *
	 * Note: Signalling display-off/display-on should normally be done from
	 * some sort of display state notifier. As that is not available, signal
	 * it here.
	 */

	status = ssam_ctrl_notif_display_off(c);
	if (status) {
		ssam_err(c, "pm: display-off notification failed: %d\n", status);
		return status;
	}

	status = ssam_ctrl_notif_d0_exit(c);
	if (status) {
		ssam_err(c, "pm: D0-exit notification failed: %d\n", status);
		goto err_notif;
	}

	if (device_may_wakeup(dev)) {
		status = enable_irq_wake(c->irq.num);
		if (status) {
			ssam_err(c, "failed to disable wake IRQ: %d\n", status);
			goto err_irq;
		}

		c->irq.wakeup_enabled = true;
	} else {
		c->irq.wakeup_enabled = false;
	}

	WARN_ON(ssam_controller_suspend(c));
	return 0;

err_irq:
	ssam_ctrl_notif_d0_entry(c);
err_notif:
	ssam_ctrl_notif_display_on(c);
	return status;
}

static int surface_sam_ssh_resume(struct device *dev)
{
	struct ssam_controller *c = dev_get_drvdata(dev);
	int status;

	WARN_ON(ssam_controller_resume(c));

	/*
	 * Try to disable IRQ wakeup (if specified), signal display-on and
	 * D0-entry. In case of errors, log them and try to restore normal
	 * operation state as far as possible.
	 *
	 * Note: Signalling display-off/display-on should normally be done from
	 * some sort of display state notifier. As that is not available, signal
	 * it here.
	 */

	if (c->irq.wakeup_enabled) {
		status = disable_irq_wake(c->irq.num);
		if (status)
			ssam_err(c, "failed to disable wake IRQ: %d\n", status);

		c->irq.wakeup_enabled = false;
	}

	status = ssam_ctrl_notif_d0_entry(c);
	if (status)
		ssam_err(c, "pm: display-on notification failed: %d\n", status);

	status = ssam_ctrl_notif_display_on(c);
	if (status)
		ssam_err(c, "pm: D0-entry notification failed: %d\n", status);

	return 0;
}

static SIMPLE_DEV_PM_OPS(surface_sam_ssh_pm_ops, surface_sam_ssh_suspend,
			 surface_sam_ssh_resume);


/* -- Device/driver setup. -------------------------------------------------- */

static struct ssam_controller ssam_controller = {
	.state = SSAM_CONTROLLER_UNINITIALIZED,
};
static DEFINE_MUTEX(ssam_controller_lock);

static int __ssam_client_link(struct ssam_controller *c, struct device *client)
{
	const u32 flags = DL_FLAG_PM_RUNTIME | DL_FLAG_AUTOREMOVE_CONSUMER;
	struct device_link *link;
	struct device *ctrldev;

	if (smp_load_acquire(&c->state) != SSAM_CONTROLLER_STARTED)
		return -ENXIO;

	if ((ctrldev = ssam_controller_device(c)) == NULL)
		return -ENXIO;

	if ((link = device_link_add(client, ctrldev, flags)) == NULL)
		return -ENOMEM;

	/*
	 * Return -ENXIO if supplier driver is on its way to be removed. In this
	 * case, the controller won't be around for much longer and the device
	 * link is not going to save us any more, as unbinding is already in
	 * progress.
	 */
	if (link->status == DL_STATE_SUPPLIER_UNBIND)
		return -ENXIO;

	return 0;
}

int ssam_client_bind(struct device *client, struct ssam_controller **ctrl)
{
	struct ssam_controller *c = &ssam_controller;
	int status;

	mutex_lock(&ssam_controller_lock);
	status = __ssam_client_link(c, client);
	mutex_unlock(&ssam_controller_lock);

	*ctrl = status == 0 ? c : NULL;
	return status;
}
EXPORT_SYMBOL_GPL(ssam_client_bind);


static int surface_sam_ssh_probe(struct serdev_device *serdev)
{
	struct ssam_controller *ctrl = &ssam_controller;
	acpi_handle *ssh = ACPI_HANDLE(&serdev->dev);
	int status;

	if (gpiod_count(&serdev->dev, NULL) < 0)
		return -ENODEV;

	status = devm_acpi_dev_add_driver_gpios(&serdev->dev, ssam_acpi_gpios);
	if (status)
		return status;

	// set up EC
	mutex_lock(&ssam_controller_lock);

	// initialize controller
	status = ssam_controller_init(ctrl, serdev);
	if (status)
		goto err_ctrl_init;

	// set up serdev device
	serdev_device_set_drvdata(serdev, ctrl);
	serdev_device_set_client_ops(serdev, &ssam_serdev_ops);
	status = serdev_device_open(serdev);
	if (status)
		goto err_devopen;

	status = ssam_serdev_setup_via_acpi(ssh, serdev);
	if (ACPI_FAILURE(status))
		goto err_devinit;

	// start controller
	status = ssam_controller_start(ctrl);
	if (status)
		goto err_devinit;

	// initial SAM requests: log version, notify default/init power states
	status = ssam_log_firmware_version(ctrl);
	if (status)
		goto err_initrq;

	status = ssam_ctrl_notif_d0_entry(ctrl);
	if (status)
		goto err_initrq;

	status = ssam_ctrl_notif_display_on(ctrl);
	if (status)
		goto err_initrq;

	// setup IRQ
	status = ssam_irq_setup(ctrl);
	if (status)
		goto err_initrq;

	mutex_unlock(&ssam_controller_lock);

	/*
	 * TODO: The EC can wake up the system via the associated GPIO interrupt
	 *       in multiple situations. One of which is the remaining battery
	 *       capacity falling below a certain threshold. Normally, we should
	 *       use the device_init_wakeup function, however, the EC also seems
	 *       to have other reasons for waking up the system and it seems
	 *       that Windows has additional checks whether the system should be
	 *       resumed. In short, this causes some spurious unwanted wake-ups.
	 *       For now let's thus default power/wakeup to false.
	 */
	device_set_wakeup_capable(&serdev->dev, true);
	acpi_walk_dep_device_list(ssh);

	return 0;

err_initrq:
	ssam_controller_shutdown(ctrl);
err_devinit:
	serdev_device_close(serdev);
err_devopen:
	ssam_controller_destroy(ctrl);
err_ctrl_init:
	serdev_device_set_drvdata(serdev, NULL);
	mutex_unlock(&ssam_controller_lock);
	return status;
}

static void surface_sam_ssh_remove(struct serdev_device *serdev)
{
	struct ssam_controller *ctrl = serdev_device_get_drvdata(serdev);
	int status;

	mutex_lock(&ssam_controller_lock);
	ssam_irq_free(ctrl);

	// suspend EC and disable events
	status = ssam_ctrl_notif_display_off(ctrl);
	if (status) {
		dev_err(&serdev->dev, "display-off notification failed: %d\n",
			status);
	}

	status = ssam_ctrl_notif_d0_exit(ctrl);
	if (status) {
		dev_err(&serdev->dev, "D0-exit notification failed: %d\n",
			status);
	}

	ssam_controller_shutdown(ctrl);

	// shut down actual transport
	serdev_device_wait_until_sent(serdev, 0);
	serdev_device_close(serdev);

	ssam_controller_destroy(ctrl);

	device_set_wakeup_capable(&serdev->dev, false);
	serdev_device_set_drvdata(serdev, NULL);
	mutex_unlock(&ssam_controller_lock);
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
		.shutdown = surface_sam_ssh_shutdown,
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};


/* -- Module setup. --------------------------------------------------------- */

static int __init surface_sam_ssh_init(void)
{
	int status;

	status = ssh_ctrl_packet_cache_init();
	if (status)
		goto err_cpkg;

	status = ssam_event_item_cache_init();
	if (status)
		goto err_evitem;

	status = serdev_device_driver_register(&surface_sam_ssh);
	if (status)
		goto err_register;

	return 0;

err_register:
	ssam_event_item_cache_destroy();
err_evitem:
	ssh_ctrl_packet_cache_destroy();
err_cpkg:
	return status;
}

static void __exit surface_sam_ssh_exit(void)
{
	serdev_device_driver_unregister(&surface_sam_ssh);
	ssam_event_item_cache_destroy();
	ssh_ctrl_packet_cache_destroy();
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
