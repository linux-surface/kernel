// SPDX-License-Identifier: GPL-2.0-or-later

#include <asm/unaligned.h>
#include <linux/atomic.h>
#include <linux/fault-inject.h>
#include <linux/jiffies.h>
#include <linux/kfifo.h>
#include <linux/kref.h>
#include <linux/kthread.h>
#include <linux/ktime.h>
#include <linux/list.h>
#include <linux/serdev.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>

#include <linux/surface_aggregator_module.h>

#include "ssh_packet_layer.h"
#include "ssh_protocol.h"

#include "ssam_trace.h"


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

void ssh_packet_put(struct ssh_packet *packet)
{
	kref_put(&packet->refcnt, __ssh_ptl_packet_release);
}
EXPORT_SYMBOL_GPL(ssh_packet_put);

static inline u8 ssh_packet_get_seq(struct ssh_packet *packet)
{
	return packet->data.ptr[SSH_MSGOFFSET_FRAME(seq)];
}


void ssh_packet_init(struct ssh_packet *packet,
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

int ssh_ctrl_packet_cache_init(void)
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

void ssh_ctrl_packet_cache_destroy(void)
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

	list_add_tail(&ssh_packet_get(packet)->queue_node, &ptl->queue.head);

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
	list_add_tail(&ssh_packet_get(packet)->pending_node, &ptl->pending.head);

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

void ssh_ptl_tx_wakeup(struct ssh_ptl *ptl, bool force)
{
	if (test_bit(SSH_PTL_SF_SHUTDOWN_BIT, &ptl->state))
		return;

	if (force || atomic_read(&ptl->pending.count) < SSH_PTL_MAX_PENDING) {
		WRITE_ONCE(ptl->tx.thread_signal, true);
		smp_mb__after_atomic();
		wake_up(&ptl->tx.thread_wq);
	}
}

int ssh_ptl_tx_start(struct ssh_ptl *ptl)
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


int ssh_ptl_submit(struct ssh_ptl *ptl, struct ssh_packet *p)
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
	list_add_tail(&ssh_packet_get(packet)->queue_node, head);

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

void ssh_ptl_cancel(struct ssh_packet *p)
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

int ssh_ptl_rx_start(struct ssh_ptl *ptl)
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

int ssh_ptl_rx_rcvbuf(struct ssh_ptl *ptl, const u8 *buf, size_t n)
{
	int used;

	if (test_bit(SSH_PTL_SF_SHUTDOWN_BIT, &ptl->state))
		return -ESHUTDOWN;

	used = kfifo_in(&ptl->rx.fifo, buf, n);
	if (used)
		ssh_ptl_rx_wakeup(ptl);

	return used;
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
void ssh_ptl_shutdown(struct ssh_ptl *ptl)
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

int ssh_ptl_init(struct ssh_ptl *ptl, struct serdev_device *serdev,
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

void ssh_ptl_destroy(struct ssh_ptl *ptl)
{
	kfifo_free(&ptl->rx.fifo);
	sshp_buf_free(&ptl->rx.buf);
}
