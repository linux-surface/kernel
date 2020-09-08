/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Interface for Surface System Aggregator Module (SSAM) via Surface Serial
 * Hub (SSH).
 *
 * The Surface Serial Hub (SSH) is the main communication hub for
 * communication between host and the Surface/System Aggregator Module (SSAM),
 * an embedded controller on newer Microsoft Surface devices (Book 2, Pro 5,
 * Laptops, and later). Also referred to as SAM-over-SSH. Older devices (Book
 * 1, Pro 4) use SAM-over-HID (via I2C), which this driver does not support.
 */

#ifndef _SURFACE_AGGREGATOR_MODULE_H
#define _SURFACE_AGGREGATOR_MODULE_H

#include <linux/completion.h>
#include <linux/types.h>
#include <linux/device.h>
#include <linux/kref.h>
#include <linux/ktime.h>
#include <linux/list.h>
#include <linux/mod_devicetable.h>
#include <linux/uuid.h>


/* -- Data structures for SAM-over-SSH communication. ----------------------- */

/**
 * enum ssh_frame_type - Frame types for SSH frames.
 *
 * @SSH_FRAME_TYPE_DATA_SEQ:
 *	Indicates a data frame, followed by a payload with the length specified
 *	in the ``struct ssh_frame.len`` field. This frame is sequenced, meaning
 *	that an ACK is required.
 *
 * @SSH_FRAME_TYPE_DATA_NSQ:
 *	Same as %SSH_FRAME_TYPE_DATA_SEQ, but unsequenced, meaning that the
 *	message does not have to be ACKed.
 *
 * @SSH_FRAME_TYPE_ACK:
 *	Indicates an ACK message.
 *
 * @SSH_FRAME_TYPE_NAK:
 *	Indicates an error response for previously sent frame. In general, this
 *	means that the frame and/or payload is malformed, e.g. a CRC is wrong.
 *	For command-type payloads, this can also mean that the command is
 *	invalid.
 */
enum ssh_frame_type {
	SSH_FRAME_TYPE_DATA_SEQ = 0x80,
	SSH_FRAME_TYPE_DATA_NSQ = 0x00,
	SSH_FRAME_TYPE_ACK	= 0x40,
	SSH_FRAME_TYPE_NAK	= 0x04,
};

/**
 * struct ssh_frame - SSH communication frame.
 * @type: The type of the frame. See &enum ssh_frame_type.
 * @len:  The length of the frame payload directly following the CRC for this
 *        frame. Does not include the final CRC for that payload.
 * @seq:  The sequence number for this message/exchange.
 */
struct ssh_frame {
	u8 type;
	__le16 len;
	u8 seq;
} __packed;

static_assert(sizeof(struct ssh_frame) == 4);

/*
 * SSH_FRAME_MAX_PAYLOAD_SIZE - Maximum SSH frame payload length in bytes.
 *
 * This is the physical maximum length of the protocol. Implementations may
 * set a more constrained limit.
 */
#define SSH_FRAME_MAX_PAYLOAD_SIZE	U16_MAX

/**
 * enum ssh_payload_type - Type indicator for the SSH payload.
 * @SSH_PLD_TYPE_CMD: The payload is a command structure with optional command
 *                    payload.
 */
enum ssh_payload_type {
	SSH_PLD_TYPE_CMD = 0x80,
};

/**
 * struct ssh_command - Payload of a command-type frame.
 * @type:    The type of the payload. See &enum ssh_payload_type. Should be
 *           SSH_PLD_TYPE_CMD for this struct.
 * @tc:      Command target category.
 * @tid_out: Output target ID. Should be zero if this an incoming (EC to host)
 *           message.
 * @tid_in:  Input target ID. Should be zero if this is an outgoing (host to
 *           EC) message.
 * @iid:     Instance ID.
 * @rqid:    Request ID. Used to match requests with responses and differentiate
 *           between responses and events.
 * @cid:     Command ID.
 */
struct ssh_command {
	u8 type;
	u8 tc;
	u8 tid_out;
	u8 tid_in;
	u8 iid;
	__le16 rqid;
	u8 cid;
} __packed;

static_assert(sizeof(struct ssh_command) == 8);

/*
 * SSH_COMMAND_MAX_PAYLOAD_SIZE - Maximum SSH command payload length in bytes.
 *
 * This is the physical maximum length of the protocol. Implementations may
 * set a more constrained limit.
 */
#define SSH_COMMAND_MAX_PAYLOAD_SIZE \
	(SSH_FRAME_MAX_PAYLOAD_SIZE - sizeof(struct ssh_command))

/*
 * SSH_MSG_LEN_BASE - Base-length of a SSH message.
 *
 * This is the minimum number of bytes required to form a message. The actual
 * message length is SSH_MSG_LEN_BASE plus the length of the frame payload.
 */
#define SSH_MSG_LEN_BASE	(sizeof(struct ssh_frame) + 3ull * sizeof(u16))

/*
 * SSH_MSG_LEN_CTRL - Length of a SSH control message.
 *
 * This is the length of a SSH control message, which is equal to a SSH
 * message without any payload.
 */
#define SSH_MSG_LEN_CTRL	SSH_MSG_LEN_BASE

/**
 * SSH_MESSAGE_LENGTH() - Comute lenght of SSH message.
 * @payload_size: Length of the payload inside the SSH frame.
 *
 * Return: Returns the length of a SSH message with payload of specified size.
 */
#define SSH_MESSAGE_LENGTH(payload_size) (SSH_MSG_LEN_BASE + payload_size)

/**
 * SSH_COMMAND_MESSAGE_LENGTH() - Compute length of SSH command message.
 * @payload_size: Length of the command payload.
 *
 * Return: Returns the length of a SSH command message with command payload of
 * specified size.
 */
#define SSH_COMMAND_MESSAGE_LENGTH(payload_size) \
	SSH_MESSAGE_LENGTH(sizeof(struct ssh_command) + payload_size)

/**
 * SSH_MSGOFFSET_FRAME() - Compute offset in SSH message to specified field in
 * frame.
 * @field: The field for which the offset should be computed.
 *
 * Return: Returns the offset of the specified &struct ssh_frame field in the
 * raw SSH message data as.
 */
#define SSH_MSGOFFSET_FRAME(field) \
	(sizeof(u16) + offsetof(struct ssh_frame, field))

/**
 * SSH_MSGOFFSET_COMMAND() - Compute offset in SSH message to specified field
 * in command.
 * @field: The field for which the offset should be computed.
 *
 * Return: Returns the offset of the specified &struct ssh_command field in
 * the raw SSH message data.
 */
#define SSH_MSGOFFSET_COMMAND(field) \
	(2ull * sizeof(u16) + sizeof(struct ssh_frame) \
		+ offsetof(struct ssh_command, field))

/**
 * struct ssam_span - Reference to a buffer region.
 * @ptr: Pointer to the buffer region.
 * @len: Length of the buffer region.
 *
 * A reference to a (non-owned) buffer segment, consisting of pointer and
 * length. Use of this struct indicates non-owned data, i.e. data of which the
 * life-time is managed (i.e. it is allocated/freed) via another pointer.
 */
struct ssam_span {
	u8    *ptr;
	size_t len;
};


/* -- Packet transport layer (ptl). ----------------------------------------- */

/**
 * enum ssh_packet_base_priority - Base priorities for &struct ssh_packet.
 * @SSH_PACKET_PRIORITY_FLUSH: Base priority for flush packets.
 * @SSH_PACKET_PRIORITY_DATA:  Base priority for normal data paackets.
 * @SSH_PACKET_PRIORITY_NAK:   Base priority for NAK packets.
 * @SSH_PACKET_PRIORITY_ACK:   Base priority for ACK packets.
 */
enum ssh_packet_base_priority {
	SSH_PACKET_PRIORITY_FLUSH = 0,	/* same as DATA to sequence flush */
	SSH_PACKET_PRIORITY_DATA  = 0,
	SSH_PACKET_PRIORITY_NAK   = 1,
	SSH_PACKET_PRIORITY_ACK   = 2,
};

/*
 * Same as SSH_PACKET_PRIORITY() below, only with actual values.
 */
#define __SSH_PACKET_PRIORITY(base, try) \
	(((base) << 4) | ((try) & 0x0f))

/**
 * SSH_PACKET_PRIORITY() - Compute packet priority from base priority and
 * number of tries.
 * @base: The base priority as suffix of &enum ssh_packet_base_priority, e.g.
 *        ``FLUSH``, ``DATA``, ``ACK``, or ``NAK``.
 * @try:  The number of tries (must be less than 16).
 *
 * Compute the combined packet priority. The combined priority is dominated by
 * the base priority, whereas the number of (re-)tries decides the precedence
 * of packets with the same base priority, giving higher priority to packets
 * that already have more tries.
 *
 * Return: Returns the computed priority as value fitting inside a &u8. A
 * higher number means a higher priority.
 */
#define SSH_PACKET_PRIORITY(base, try) \
	__SSH_PACKET_PRIORITY(SSH_PACKET_PRIORITY_##base, (try))

/**
 * ssh_packet_priority_get_try() - Get number of tries from packet priority.
 * @priority: The packet priority.
 *
 * Return: Returns the number of tries encoded in the specified packet
 * priority.
 */
static inline u8 ssh_packet_priority_get_try(u8 priority)
{
	return priority & 0x0f;
}

/**
 * ssh_packet_priority_get_base - Get base priority from packet priority.
 * @priority: The packet priority.
 *
 * Return: Returns the base priority encoded in the given packet priority.
 */
static inline u8 ssh_packet_priority_get_base(u8 priority)
{
	return (priority & 0xf0) >> 4;
}


enum ssh_packet_flags {
	/* state flags */
	SSH_PACKET_SF_LOCKED_BIT,
	SSH_PACKET_SF_QUEUED_BIT,
	SSH_PACKET_SF_PENDING_BIT,
	SSH_PACKET_SF_TRANSMITTING_BIT,
	SSH_PACKET_SF_TRANSMITTED_BIT,
	SSH_PACKET_SF_ACKED_BIT,
	SSH_PACKET_SF_CANCELED_BIT,
	SSH_PACKET_SF_COMPLETED_BIT,

	/* type flags */
	SSH_PACKET_TY_FLUSH_BIT,
	SSH_PACKET_TY_SEQUENCED_BIT,
	SSH_PACKET_TY_BLOCKING_BIT,

	/* mask for state flags */
	SSH_PACKET_FLAGS_SF_MASK =
		  BIT(SSH_PACKET_SF_LOCKED_BIT)
		| BIT(SSH_PACKET_SF_QUEUED_BIT)
		| BIT(SSH_PACKET_SF_PENDING_BIT)
		| BIT(SSH_PACKET_SF_TRANSMITTING_BIT)
		| BIT(SSH_PACKET_SF_TRANSMITTED_BIT)
		| BIT(SSH_PACKET_SF_ACKED_BIT)
		| BIT(SSH_PACKET_SF_CANCELED_BIT)
		| BIT(SSH_PACKET_SF_COMPLETED_BIT),

	/* mask for type flags */
	SSH_PACKET_FLAGS_TY_MASK =
		  BIT(SSH_PACKET_TY_FLUSH_BIT)
		| BIT(SSH_PACKET_TY_SEQUENCED_BIT)
		| BIT(SSH_PACKET_TY_BLOCKING_BIT),
};


struct ssh_ptl;
struct ssh_packet;

/**
 * struct ssh_packet_ops - Callback operations for a SSH packet.
 * @release:  Function called when the packet reference count reaches zero.
 *            This callback must be relied upon to ensure that the packet has
 *            left the transport system(s).
 * @complete: Function called when the packet is completed, either with
 *            success or failure. In case of failure, the reason for the
 *            failure is indicated by the value of the provided status code
 *            argument. This value will be zero in case of success. Note that
 *            a call to this callback does not guarantee that the packet is
 *            not in use by the transport system any more.
 */
struct ssh_packet_ops {
	void (*release)(struct ssh_packet *p);
	void (*complete)(struct ssh_packet *p, int status);
};

/**
 * struct ssh_packet - SSH transport packet.
 * @ptl:      Pointer to the packet transport layer. May be %NULL if the packet
 *            (or enclosing request) has not been submitted yet.
 * @refcnt:   Reference count of the packet.
 * @priority: Priority of the packet. Must be computed via
 *            SSH_PACKET_PRIORITY().
 * @data:     Raw message data.
 * @data.len: Length of the raw message data.
 * @data.ptr: Pointer to the raw message data buffer.
 * @state:    State and type flags describing current packet state (dynamic)
 *            and type (static). See &enum ssh_packet_flags for possible
 *            options.
 * @timestamp: Timestamp specifying when the latest transmission of a
 *            currently pending packet has been started. May be %KTIME_MAX
 *            before or in-between transmission attempts. Used for the packet
 *            timeout implementation.
 * @queue_node:	The list node for the packet queue.
 * @pending_node: The list node for the set of pending packets.
 * @ops:      Packet operations.
 */
struct ssh_packet {
	struct ssh_ptl *ptl;
	struct kref refcnt;

	u8 priority;

	struct {
		size_t len;
		u8 *ptr;
	} data;

	unsigned long state;
	ktime_t timestamp;

	struct list_head queue_node;
	struct list_head pending_node;

	const struct ssh_packet_ops *ops;
};

struct ssh_packet *ssh_packet_get(struct ssh_packet *p);
void ssh_packet_put(struct ssh_packet *p);

/**
 * ssh_packet_set_data() - Set raw message data of packet.
 * @p:   The packet for which the message data should be set.
 * @ptr: Pointer to the memory holding the message data.
 * @len: Length of the message data.
 *
 * Sets the raw message data buffer of the packet to the provided memory. The
 * memory is not copied. Instead, the caller is responsible for management
 * (i.e. allocation and deallocation) of the memory. The caller must ensure
 * that the provided memory is valid and contains a valid SSH message,
 * starting from the time of submission of the packet until the ``release``
 * callback has been called. During this time, the memory may not be altered
 * in any way.
 */
static inline void ssh_packet_set_data(struct ssh_packet *p, u8 *ptr, size_t len)
{
	p->data.ptr = ptr;
	p->data.len = len;
}


/* -- Request transport layer (rtl). ---------------------------------------- */

enum ssh_request_flags {
	/* state flags */
	SSH_REQUEST_SF_LOCKED_BIT,
	SSH_REQUEST_SF_QUEUED_BIT,
	SSH_REQUEST_SF_PENDING_BIT,
	SSH_REQUEST_SF_TRANSMITTING_BIT,
	SSH_REQUEST_SF_TRANSMITTED_BIT,
	SSH_REQUEST_SF_RSPRCVD_BIT,
	SSH_REQUEST_SF_CANCELED_BIT,
	SSH_REQUEST_SF_COMPLETED_BIT,

	/* type flags */
	SSH_REQUEST_TY_FLUSH_BIT,
	SSH_REQUEST_TY_HAS_RESPONSE_BIT,

	/* mask for state flags */
	SSH_REQUEST_FLAGS_SF_MASK =
		  BIT(SSH_REQUEST_SF_LOCKED_BIT)
		| BIT(SSH_REQUEST_SF_QUEUED_BIT)
		| BIT(SSH_REQUEST_SF_PENDING_BIT)
		| BIT(SSH_REQUEST_SF_TRANSMITTING_BIT)
		| BIT(SSH_REQUEST_SF_TRANSMITTED_BIT)
		| BIT(SSH_REQUEST_SF_RSPRCVD_BIT)
		| BIT(SSH_REQUEST_SF_CANCELED_BIT)
		| BIT(SSH_REQUEST_SF_COMPLETED_BIT),

	/* mask for type flags */
	SSH_REQUEST_FLAGS_TY_MASK =
		  BIT(SSH_REQUEST_TY_FLUSH_BIT)
		| BIT(SSH_REQUEST_TY_HAS_RESPONSE_BIT),
};


struct ssh_rtl;
struct ssh_request;

/**
 * struct ssh_request_ops - Callback operations for a SSH request.
 * @release:  Function called when the request's reference count reaches zero.
 *            This callback must be relied upon to ensure that the request has
 *            left the transport systems (both, packet an request systems).
 * @complete: Function called when the request is completed, either with
 *            success or failure. The command data for the request response
 *            is provided via the &struct ssh_command parameter (``cmd``),
 *            the command payload of the request response via the &struct
 *            ssh_span parameter (``data``).
 *
 *            If the request does not have any response or has not been
 *            completed with success, both ``cmd`` and ``data`` parameters will
 *            be NULL. If the request response does not have any command
 *            payload, the ``data`` span will be an empty (zero-length) span.
 *
 *            In case of failure, the reason for the failure is indicated by
 *            the value of the provided status code argument (``status``). This
 *            value will be zero in case of success.
 *
 *            Note that a call to this callback does not guarantee that the
 *            request is not in use by the transport systems any more.
 */
struct ssh_request_ops {
	void (*release)(struct ssh_request *rqst);
	void (*complete)(struct ssh_request *rqst,
			 const struct ssh_command *cmd,
			 const struct ssam_span *data, int status);
};

/**
 * struct ssh_request - SSH transport request.
 * @packet: The underlying SSH transport packet.
 * @node:   List node for the request queue and pending set.
 * @state:  State and type flags describing current request state (dynamic)
 *          and type (static). See &enum ssh_request_flags for possible
 *          options.
 * @timestamp: Timestamp specifying when we start waiting on the respnse of the
 *          request. This is set once the underlying packet has been completed
 *          and may be %KTIME_MAX before that, or when the request does not
 *          expect a response. Used for the request timeout implementation.
 * @ops:    Request Operations.
 */
struct ssh_request {
	struct ssh_packet packet;
	struct list_head node;

	unsigned long state;
	ktime_t timestamp;

	const struct ssh_request_ops *ops;
};

/**
 * to_ssh_request() - Cast a SSH packet to its enclosing SSH request.
 * @p: The packet to cast.
 *
 * Casts the given &struct ssh_packet to its enclosing &struct ssh_request.
 * The caller is responsible for making sure that the packet is actually
 * wrapped in a &struct ssh_request.
 *
 * Return: Returns the &struct ssh_request wrapping the provided packet.
 */
static inline struct ssh_request *to_ssh_request(struct ssh_packet *p)
{
	return container_of(p, struct ssh_request, packet);
}

/**
 * ssh_request_get() - Increment reference count of request.
 * @r: The request to increment the reference count of.
 *
 * Increments the reference count of the given request by incrementing the
 * reference count of the underlying &struct ssh_packet, enclosed in it.
 *
 * See also ssh_request_put(), ssh_packet_get().
 *
 * Return: Returns the request provided as input.
 */
static inline struct ssh_request *ssh_request_get(struct ssh_request *r)
{
	ssh_packet_get(&r->packet);
	return r;
}

/**
 * ssh_request_put() - Decrement reference count of request.
 * @r: The request to decrement the reference count of.
 *
 * Decrements the reference count of the given request by decrementing the
 * reference count of the underlying &struct ssh_packet, enclosed in it. If
 * the reference count reaches zero, the ``release`` callback specified in the
 * request's &struct ssh_request_ops, i.e. ``r->ops->release``, will be
 * called.
 *
 * See also ssh_request_get(), ssh_packet_put().
 */
static inline void ssh_request_put(struct ssh_request *r)
{
	ssh_packet_put(&r->packet);
}

/**
 * ssh_request_set_data() - Set raw message data of request.
 * @r:   The request for which the message data should be set.
 * @ptr: Pointer to the memory holding the message data.
 * @len: Length of the message data.
 *
 * Sets the raw message data buffer of the underlying packet to the specified
 * buffer. Does not copy the actual message data, just sets the buffer pointer
 * and length. Refer to ssh_packet_set_data() for more details.
 */
static inline void ssh_request_set_data(struct ssh_request *r, u8 *ptr, size_t len)
{
	ssh_packet_set_data(&r->packet, ptr, len);
}


/* -- Main data types and definitions --------------------------------------- */

enum ssam_ssh_tc {
	/* Known SSH/EC target categories. */
				// category 0x00 is invalid for EC use
	SSAM_SSH_TC_SAM = 0x01,	// generic system functionality, real-time clock
	SSAM_SSH_TC_BAT = 0x02,	// battery/power subsystem
	SSAM_SSH_TC_TMP = 0x03,	// thermal subsystem
	SSAM_SSH_TC_PMC = 0x04,
	SSAM_SSH_TC_FAN = 0x05,
	SSAM_SSH_TC_PoM = 0x06,
	SSAM_SSH_TC_DBG = 0x07,
	SSAM_SSH_TC_KBD = 0x08,	// legacy keyboard (Laptop 1/2)
	SSAM_SSH_TC_FWU = 0x09,
	SSAM_SSH_TC_UNI = 0x0a,
	SSAM_SSH_TC_LPC = 0x0b,
	SSAM_SSH_TC_TCL = 0x0c,
	SSAM_SSH_TC_SFL = 0x0d,
	SSAM_SSH_TC_KIP = 0x0e,
	SSAM_SSH_TC_EXT = 0x0f,
	SSAM_SSH_TC_BLD = 0x10,
	SSAM_SSH_TC_BAS = 0x11,	// detachment system (Surface Book 2/3)
	SSAM_SSH_TC_SEN = 0x12,
	SSAM_SSH_TC_SRQ = 0x13,
	SSAM_SSH_TC_MCU = 0x14,
	SSAM_SSH_TC_HID = 0x15,	// generic HID input subsystem
	SSAM_SSH_TC_TCH = 0x16,
	SSAM_SSH_TC_BKL = 0x17,
	SSAM_SSH_TC_TAM = 0x18,
	SSAM_SSH_TC_ACC = 0x19,
	SSAM_SSH_TC_UFI = 0x1a,
	SSAM_SSH_TC_USC = 0x1b,
	SSAM_SSH_TC_PEN = 0x1c,
	SSAM_SSH_TC_VID = 0x1d,
	SSAM_SSH_TC_AUD = 0x1e,
	SSAM_SSH_TC_SMC = 0x1f,
	SSAM_SSH_TC_KPD = 0x20,
	SSAM_SSH_TC_REG = 0x21,

	/* Special values. For driver use only, do not use with EC. */
	SSAM_SSH_TC__HUB = 0x00, // not an actual category, used in for hubs
};

struct ssam_controller;

/**
 * enum ssam_event_flags - Flags for enabling/disabling SAM events
 * @SSAM_EVENT_SEQUENCED: The event will be sent via a sequenced data frame.
 */
enum ssam_event_flags {
	SSAM_EVENT_SEQUENCED = BIT(0),
};

/**
 * struct ssam_event - SAM event sent from the EC to the host.
 * @target_category: Target category of the event source. See &enum ssam_ssh_tc.
 * @target_id:       Target ID of the event source.
 * @command_id:      Command ID of the event.
 * @instance_id:     Instance ID of the event source.
 * @length:          Length of the event payload in bytes.
 * @data:            Event payload data.
 */
struct ssam_event {
	u8 target_category;
	u8 target_id;
	u8 command_id;
	u8 instance_id;
	u16 length;
	u8 data[0];
};

/**
 * enum ssam_request_flags - Flags for SAM requests.
 *
 * @SSAM_REQUEST_HAS_RESPONSE:
 *	Specifies that the request expects a response. If not set, the request
 *	will be directly completed after its underlying packet has been
 *	transmitted. If set, the request transport system waits for a response
 *	of the request.
 *
 * @SSAM_REQUEST_UNSEQUENCED:
 *	Specifies that the request should be transmitted via an unsequenced
 *	packet. If set, the request must not have a response, meaning that this
 *	flag and the %SSAM_REQUEST_HAS_RESPONSE flag are mutually exclusive.
 */
enum ssam_request_flags {
	SSAM_REQUEST_HAS_RESPONSE = BIT(0),
	SSAM_REQUEST_UNSEQUENCED  = BIT(1),
};

/**
 * struct ssam_request - SAM request description.
 * @target_category: Category of the request's target. See &enum ssam_ssh_tc.
 * @target_id:       ID of the request's target.
 * @command_id:      Command ID of the request.
 * @instance_id:     Instance ID of the request's target.
 * @flags:           Flags for the request. See &enum ssam_request_flags.
 * @length:          Length of the request payload in bytes.
 * @payload:         Request payload data.
 *
 * This struct fully describes a SAM request with payload. It is intended to
 * help set up the actual transport struct, e.g. &struct ssam_request_sync,
 * and specifically its raw message data via ssam_request_write_data().
 */
struct ssam_request {
	u8 target_category;
	u8 target_id;
	u8 command_id;
	u8 instance_id;
	u16 flags;
	u16 length;
	const u8 *payload;
};

/**
 * struct ssam_response - Response buffer for SAM request.
 * @capacity: Capacity of the buffer, in bytes.
 * @length:   Length of the actual data stored in the memory pointed to by
 *            @pointer, in bytes. Set by the transport system.
 * @pointer:  Pointer to the buffer's memory, storing the response payload data.
 */
struct ssam_response {
	size_t capacity;
	size_t length;
	u8 *pointer;
};


struct ssam_controller *ssam_get_controller(void);
int ssam_client_link(struct ssam_controller *ctrl, struct device *client);
int ssam_client_bind(struct device *client, struct ssam_controller **ctrl);

struct device *ssam_controller_device(struct ssam_controller *c);

struct ssam_controller *ssam_controller_get(struct ssam_controller *c);
void ssam_controller_put(struct ssam_controller *c);

void ssam_controller_statelock(struct ssam_controller *c);
void ssam_controller_stateunlock(struct ssam_controller *c);

ssize_t ssam_request_write_data(struct ssam_span *buf,
				struct ssam_controller *ctrl,
				struct ssam_request *spec);


/* -- Synchronous request interface. ---------------------------------------- */

/**
 * struct ssam_request_sync - Synchronous SAM request struct.
 * @base:   Underlying SSH request.
 * @comp:   Completion used to signal full completion of the request. After the
 *          request has been submitted, this struct may only be modified or
 *          deallocated after the completion has been signaled.
 *          request has been submitted,
 * @resp:   Buffer to store the response.
 * @status: Status of the request, set after the base request has been
 *          completed or has failed.
 */
struct ssam_request_sync {
	struct ssh_request base;
	struct completion comp;
	struct ssam_response *resp;
	int status;
};

int ssam_request_sync_alloc(size_t payload_len, gfp_t flags,
			    struct ssam_request_sync **rqst,
			    struct ssam_span *buffer);

void ssam_request_sync_free(struct ssam_request_sync *rqst);

void ssam_request_sync_init(struct ssam_request_sync *rqst,
			    enum ssam_request_flags flags);

/**
 * ssam_request_sync_set_data - Set message data of a synchronous request.
 * @rqst: The request.
 * @ptr:  Pointer to the request message data.
 * @len:  Length of the request message data.
 *
 * Set the request message data of a synchronous request. The provided buffer
 * needs to live until the request has been completed.
 */
static inline void ssam_request_sync_set_data(struct ssam_request_sync *rqst,
					      u8 *ptr, size_t len)
{
	ssh_request_set_data(&rqst->base, ptr, len);
}

/**
 * ssam_request_sync_set_resp - Set response buffer of a synchronous request.
 * @rqst: The request.
 * @resp: The response buffer.
 *
 * Sets the response buffer ot a synchronous request. This buffer will store
 * the response of the request after it has been completed. May be %NULL if
 * no response is expected.
 */
static inline void ssam_request_sync_set_resp(struct ssam_request_sync *rqst,
					      struct ssam_response *resp)
{
	rqst->resp = resp;
}

int ssam_request_sync_submit(struct ssam_controller *ctrl,
			     struct ssam_request_sync *rqst);

/**
 * ssam_request_sync_wait - Wait for completion of a synchronous request.
 * @rqst: The request to wait for.
 *
 * Wait for completion and release of a synchronous request. After this
 * function terminates, the request is guaranteed to have left the transport
 * system. After successful submission of a request, this function must be
 * called before accessing the response of the request, freeing the request,
 * or freeing any of the buffers associated with the request.
 *
 * This function must not be called if the request has not been submitted yet
 * and may lead to a deadlock/infinite wait if a subsequent request submission
 * fails in that case, due to the completion never triggering.
 *
 * Return: Returns the status of the given request, which is set on completion
 * of the packet. This value is zero on success and negative on failure.
 */
static inline int ssam_request_sync_wait(struct ssam_request_sync *rqst)
{
	wait_for_completion(&rqst->comp);
	return rqst->status;
}

int ssam_request_sync(struct ssam_controller *ctrl, struct ssam_request *spec,
		      struct ssam_response *rsp);

int ssam_request_sync_with_buffer(struct ssam_controller *ctrl,
				  struct ssam_request *spec,
				  struct ssam_response *rsp,
				  struct ssam_span *buf);


/**
 * ssam_request_sync_onstack - Execute a synchronous request on the stack.
 * @ctrl: The controller via which the request is submitted.
 * @rqst: The request specification.
 * @rsp:  The response buffer.
 * @payload_len: The (maximum) request payload length.
 *
 * Allocates a synchronous request with specified payload length on the stack,
 * fully intializes it via the provided request specification, submits it, and
 * finally waits for its completion before returning its status. This helper
 * macro essentially allocates the request message buffer on the stack and
 * then calls ssam_request_sync_with_buffer().
 *
 * Note: The @payload_len parameter specifies the maximum payload length, used
 * for buffer allocation. The actual payload length may be smaller.
 *
 * Return: Returns the status of the request or any failure during setup, i.e.
 * zero on success and a negative value on failure.
 */
#define ssam_request_sync_onstack(ctrl, rqst, rsp, payload_len)			\
	({									\
		u8 __data[SSH_COMMAND_MESSAGE_LENGTH(payload_len)];		\
		struct ssam_span __buf = { &__data[0], ARRAY_SIZE(__data) };	\
										\
		ssam_request_sync_with_buffer(ctrl, rqst, rsp, &__buf);		\
	})


/**
 * struct ssam_request_spec - Blue-print specification of SAM request.
 * @target_category: Category of the request's target. See &enum ssam_ssh_tc.
 * @target_id:       ID of the request's target.
 * @command_id:      Command ID of the request.
 * @instance_id:     Instance ID of the request's target.
 * @flags:           Flags for the request. See &enum ssam_request_flags.
 *
 * Blue-print specification for a SAM request. This struct describes the
 * unique static parameters of a request (i.e. type) without specifying any of
 * its instance-specific data (e.g. payload). It is intended to be used as base
 * for defining simple request functions via the
 * ``SSAM_DEFINE_SYNC_REQUEST_x()`` family of macros.
 */
struct ssam_request_spec {
	u8 target_category;
	u8 target_id;
	u8 command_id;
	u8 instance_id;
	u8 flags;
};

/**
 * struct ssam_request_spec_md - Blue-print specification for multi-device SAM
 * request.
 * @target_category: Category of the request's target. See &enum ssam_ssh_tc.
 * @command_id:      Command ID of the request.
 * @flags:           Flags for the request. See &enum ssam_request_flags.
 *
 * Blue-print specification for a multi-device SAM request, i.e. a request
 * that is applicable to multiple device instances, described by their
 * individual target and instance IDs. This struct describes the unique static
 * parameters of a request (i.e. type) without specifying any of its
 * instance-specific data (e.g. payload) and without specifying any of its
 * device specific IDs (i.e. target and instance ID). It is intended to be
 * used as base for defining simple multi-device request functions via the
 * ``SSAM_DEFINE_SYNC_REQUEST_MD_x()`` and ``SSAM_DEFINE_SYNC_REQUEST_CL_x()``
 * families of macros.
 */
struct ssam_request_spec_md {
	u8 target_category;
	u8 command_id;
	u8 flags;
};

/**
 * SSAM_DEFINE_SYNC_REQUEST_N() - Define synchronous SAM request function
 * with neither argument nor return value.
 * @name: Name of the generated function.
 * @spec: Specification (&struct ssam_request_spec) defining the request.
 *
 * Defines a function executing the synchronous SAM request specified by
 * @spec, with the request having neither argument nor return value. The
 * generated function takes care of setting up the request struct and buffer
 * allocation, as well as execution of the request itself, returning once the
 * request has been fully completed. The required transport buffer will be
 * allocated on the stack.
 *
 * The generated function is defined as ``int name(struct ssam_controller
 * *ctrl)``, returning the status of the request, which is zero on success and
 * negative on failure. The ``ctrl`` parameter is the controller via which the
 * request is being sent.
 *
 * Refer to ssam_request_sync_onstack() for more details on the behavior of
 * the generated function.
 */
#define SSAM_DEFINE_SYNC_REQUEST_N(name, spec...)				\
	int name(struct ssam_controller *ctrl)					\
	{									\
		struct ssam_request_spec s = (struct ssam_request_spec)spec;	\
		struct ssam_request rqst;					\
										\
		rqst.target_category = s.target_category;			\
		rqst.target_id = s.target_id;					\
		rqst.command_id = s.command_id;					\
		rqst.instance_id = s.instance_id;				\
		rqst.flags = s.flags;						\
		rqst.length = 0;						\
		rqst.payload = NULL;						\
										\
		return ssam_request_sync_onstack(ctrl, &rqst, NULL, 0);		\
	}

/**
 * SSAM_DEFINE_SYNC_REQUEST_W() - Define synchronous SAM request function with
 * argument.
 * @name:  Name of the generated function.
 * @atype: Type of the request's argument.
 * @spec:  Specification (&struct ssam_request_spec) defining the request.
 *
 * Defines a function executing the synchronous SAM request specified by
 * @spec, with the request taking an argument of type @atype and having no
 * return value. The generated function takes care of setting up the request
 * struct, buffer allocation, as well as execution of the request itself,
 * returning once the request has been fully completed. The required transport
 * buffer will be allocated on the stack.
 *
 * The generated function is defined as ``int name(struct ssam_controller
 * *ctrl, const atype *arg)``, returning the status of the request, which is
 * zero on success and negative on failure. The ``ctrl`` parameter is the
 * controller via which the request is sent. The request argument is specified
 * via the ``arg`` pointer.
 *
 * Refer to ssam_request_sync_onstack() for more details on the behavior of
 * the generated function.
 */
#define SSAM_DEFINE_SYNC_REQUEST_W(name, atype, spec...)			\
	int name(struct ssam_controller *ctrl, const atype *arg)		\
	{									\
		struct ssam_request_spec s = (struct ssam_request_spec)spec;	\
		struct ssam_request rqst;					\
										\
		rqst.target_category = s.target_category;			\
		rqst.target_id = s.target_id;					\
		rqst.command_id = s.command_id;					\
		rqst.instance_id = s.instance_id;				\
		rqst.flags = s.flags;						\
		rqst.length = sizeof(atype);					\
		rqst.payload = (u8 *)arg;					\
										\
		return ssam_request_sync_onstack(ctrl, &rqst, NULL,		\
						 sizeof(atype));		\
	}

/**
 * SSAM_DEFINE_SYNC_REQUEST_R() - Define synchronous SAM request function with
 * return value.
 * @name:  Name of the generated function.
 * @rtype: Type of the request's return value.
 * @spec:  Specification (&struct ssam_request_spec) defining the request.
 *
 * Defines a function executing the synchronous SAM request specified by
 * @spec, with the request taking no argument but having a return value of
 * type @rtype. The generated function takes care of setting up the request
 * and response structs, buffer allocation, as well as execution of the
 * request itself, returning once the request has been fully completed. The
 * required transport buffer will be allocated on the stack.
 *
 * The generated function is defined as ``int name(struct ssam_controller
 * *ctrl, rtype *ret)``, returning the status of the request, which is zero on
 * success and negative on failure. The ``ctrl`` parameter is the controller
 * via which the request is sent. The request's return value is written to the
 * memory pointed to by the ``ret`` parameter.
 *
 * Refer to ssam_request_sync_onstack() for more details on the behavior of
 * the generated function.
 */
#define SSAM_DEFINE_SYNC_REQUEST_R(name, rtype, spec...)			\
	int name(struct ssam_controller *ctrl, rtype *ret)			\
	{									\
		struct ssam_request_spec s = (struct ssam_request_spec)spec;	\
		struct ssam_request rqst;					\
		struct ssam_response rsp;					\
		int status;							\
										\
		rqst.target_category = s.target_category;			\
		rqst.target_id = s.target_id;					\
		rqst.command_id = s.command_id;					\
		rqst.instance_id = s.instance_id;				\
		rqst.flags = s.flags | SSAM_REQUEST_HAS_RESPONSE;		\
		rqst.length = 0;						\
		rqst.payload = NULL;						\
										\
		rsp.capacity = sizeof(rtype);					\
		rsp.length = 0;							\
		rsp.pointer = (u8 *)ret;					\
										\
		status = ssam_request_sync_onstack(ctrl, &rqst, &rsp, 0);	\
		if (status)							\
			return status;						\
										\
		if (rsp.length != sizeof(rtype)) {				\
			struct device *dev = ssam_controller_device(ctrl);	\
			dev_err(dev, "rqst: invalid response length, expected "	\
				"%zu, got %zu (tc: 0x%02x, cid: 0x%02x)",	\
				sizeof(rtype), rsp.length, rqst.target_category,\
				rqst.command_id);				\
			return -EIO;						\
		}								\
										\
		return 0;							\
	}

/**
 * SSAM_DEFINE_SYNC_REQUEST_MD_N() - Define synchronous multi-device SAM
 * request function with neither argument nor return value.
 * @name: Name of the generated function.
 * @spec: Specification (&struct ssam_request_spec_md) defining the request.
 *
 * Defines a function executing the synchronous SAM request specified by
 * @spec, with the request having neither argument nor return value. Device
 * specifying parameters are not hard-coded, but instead must be provided to
 * the function. The generated function takes care of setting up the request
 * struct, buffer allocation, as well as execution of the request itself,
 * returning once the request has been fully completed. The required transport
 * buffer will be allocated on the stack.
 *
 * The generated function is defined as ``int name(struct ssam_controller
 * *ctrl, u8 tid, u8 iid)``, returning the status of the request, which is
 * zero on success and negative on failure. The ``ctrl`` parameter is the
 * controller via which the request is sent, ``tid`` the target ID for the
 * request, and ``iid`` the instance ID.
 *
 * Refer to ssam_request_sync_onstack() for more details on the behavior of
 * the generated function.
 */
#define SSAM_DEFINE_SYNC_REQUEST_MD_N(name, spec...)				\
	int name(struct ssam_controller *ctrl, u8 tid, u8 iid)			\
	{									\
		struct ssam_request_spec_md s					\
			= (struct ssam_request_spec_md)spec;			\
		struct ssam_request rqst;					\
										\
		rqst.target_category = s.target_category;			\
		rqst.target_id = tid;						\
		rqst.command_id = s.command_id;					\
		rqst.instance_id = iid;						\
		rqst.flags = s.flags;						\
		rqst.length = 0;						\
		rqst.payload = NULL;						\
										\
		return ssam_request_sync_onstack(ctrl, &rqst, NULL, 0);		\
	}

/**
 * SSAM_DEFINE_SYNC_REQUEST_MD_W() - Define synchronous multi-device SAM
 * request function with argument.
 * @name:  Name of the generated function.
 * @atype: Type of the request's argument.
 * @spec:  Specification (&struct ssam_request_spec_md) defining the request.
 *
 * Defines a function executing the synchronous SAM request specified by
 * @spec, with the request taking an argument of type @atype and having no
 * return value. Device specifying parameters are not hard-coded, but instead
 * must be provided to the function. The generated function takes care of
 * setting up the request struct, buffer allocation, as well as execution of
 * the request itself, returning once the request has been fully completed.
 * The required transport buffer will be allocated on the stack.
 *
 * The generated function is defined as ``int name(struct ssam_controller
 * *ctrl, u8 tid, u8 iid, const atype *arg)``, returning the status of the
 * request, which is zero on success and negative on failure. The ``ctrl``
 * parameter is the controller via which the request is sent, ``tid`` the
 * target ID for the request, and ``iid`` the instance ID. The request argument
 * is specified via the ``arg`` pointer.
 *
 * Refer to ssam_request_sync_onstack() for more details on the behavior of
 * the generated function.
 */
#define SSAM_DEFINE_SYNC_REQUEST_MD_W(name, atype, spec...)			\
	int name(struct ssam_controller *ctrl, u8 tid, u8 iid, const atype *arg)\
	{									\
		struct ssam_request_spec_md s					\
			= (struct ssam_request_spec_md)spec;			\
		struct ssam_request rqst;					\
										\
		rqst.target_category = s.target_category;			\
		rqst.target_id = tid;						\
		rqst.command_id = s.command_id;					\
		rqst.instance_id = iid;						\
		rqst.flags = s.flags;						\
		rqst.length = sizeof(atype);					\
		rqst.payload = (u8 *)arg;					\
										\
		return ssam_request_sync_onstack(ctrl, &rqst, NULL,		\
						 sizeof(atype));		\
	}

/**
 * SSAM_DEFINE_SYNC_REQUEST_MD_R() - Define synchronous multi-device SAM
 * request function with return value.
 * @name:  Name of the generated function.
 * @rtype: Type of the request's return value.
 * @spec:  Specification (&struct ssam_request_spec_md) defining the request.
 *
 * Defines a function executing the synchronous SAM request specified by
 * @spec, with the request taking no argument but having a return value of
 * type @rtype. Device specifying parameters are not hard-coded, but instead
 * must be provided to the function. The generated function takes care of
 * setting up the request and response structs, buffer allocation, as well as
 * execution of the request itself, returning once the request has been fully
 * completed. The required transport buffer will be allocated on the stack.
 *
 * The generated function is defined as ``int name(struct ssam_controller
 * *ctrl, u8 tid, u8 iid, rtype *ret)``, returning the status of the request,
 * which is zero on success and negative on failure. The ``ctrl`` parameter is
 * the controller via which the request is sent, ``tid`` the target ID for the
 * request, and ``iid`` the instance ID. The request's return value is written
 * to the memory pointed to by the ``ret`` parameter.
 *
 * Refer to ssam_request_sync_onstack() for more details on the behavior of
 * the generated function.
 */
#define SSAM_DEFINE_SYNC_REQUEST_MD_R(name, rtype, spec...)			\
	int name(struct ssam_controller *ctrl, u8 tid, u8 iid, rtype *ret)	\
	{									\
		struct ssam_request_spec_md s					\
			= (struct ssam_request_spec_md)spec;			\
		struct ssam_request rqst;					\
		struct ssam_response rsp;					\
		int status;							\
										\
		rqst.target_category = s.target_category;			\
		rqst.target_id = tid;						\
		rqst.command_id = s.command_id;					\
		rqst.instance_id = iid;						\
		rqst.flags = s.flags | SSAM_REQUEST_HAS_RESPONSE;		\
		rqst.length = 0;						\
		rqst.payload = NULL;						\
										\
		rsp.capacity = sizeof(rtype);					\
		rsp.length = 0;							\
		rsp.pointer = (u8 *)ret;					\
										\
		status = ssam_request_sync_onstack(ctrl, &rqst, &rsp, 0);	\
		if (status)							\
			return status;						\
										\
		if (rsp.length != sizeof(rtype)) {				\
			struct device *dev = ssam_controller_device(ctrl);	\
			dev_err(dev, "rqst: invalid response length, expected "	\
				"%zu, got %zu (tc: 0x%02x, cid: 0x%02x)",	\
				sizeof(rtype), rsp.length, rqst.target_category,\
				rqst.command_id);				\
			return -EIO;						\
		}								\
										\
		return 0;							\
	}


/* -- Event notifier/callbacks. --------------------------------------------- */

#define SSAM_NOTIF_STATE_SHIFT		2
#define SSAM_NOTIF_STATE_MASK		((1 << SSAM_NOTIF_STATE_SHIFT) - 1)

/**
 * enum ssam_notif_flags - Flags used in return values from SSAM notifier
 * callback functions.
 *
 * @SSAM_NOTIF_HANDLED:
 *	Indicates that the notification has been handled. This flag should be
 *	set by the handler if the handler can act/has acted upon the event
 *	provided to it. This flag should not be set if the handler is not a
 *	primary handler intended for the provided event.
 *
 *	If this flag has not been set by any handler after the notifier chain
 *	has been traversed, a warning will be emitted, stating that the event
 *	has not been handled.
 *
 * @SSAM_NOTIF_STOP:
 *	Indicates that the notifier traversal should stop. If this flag is
 *	returned from a notifier callback, notifier chain traversal will
 *	immediately stop and any remaining notifiers will not be called. This
 *	flag is automatically set when ssam_notifier_from_errno() is called
 *	with a negative error value.
 */
enum ssam_notif_flags {
	SSAM_NOTIF_HANDLED = BIT(0),
	SSAM_NOTIF_STOP    = BIT(1),
};


struct ssam_event_notifier;

typedef u32 (*ssam_notifier_fn_t)(struct ssam_event_notifier *nf,
				  const struct ssam_event *event);

/**
 * struct ssam_notifier_block - Base notifier block for SSAM event
 * notifications.
 * @next:     The next notifier block in order of priority.
 * @fn:       The callback function of this notifier. This function takes the
 *            respective notifier block and event as input and should return
 *            a notifier value, which can either be obtained from the flags
 *            provided in &enum ssam_notif_flags, converted from a standard
 *            error value via ssam_notifier_from_errno(), or a combination of
 *            both (e.g. ``ssam_notifier_from_errno(e) | SSAM_NOTIF_HANDLED``).
 * @priority: Priority value determining the order in which notifier callbacks
 *            will be called. A higher value means higher priority, i.e. the
 *            associated callback will be executed earlier than other (lower
 *            priority) callbacks.
 */
struct ssam_notifier_block {
	struct ssam_notifier_block __rcu *next;
	ssam_notifier_fn_t fn;
	int priority;
};

/**
 * ssam_notifier_from_errno() - Convert standard error value to notifier
 * return code.
 * @err: The error code to convert, must be negative (in case of failure) or
 *       zero (in case of success).
 *
 * Return: Returns the notifier return value obtained by converting the
 * specified @err value. In case @err is negative, the %SSAM_NOTIF_STOP flag
 * will be set, causing notifier call chain traversal to abort.
 */
static inline u32 ssam_notifier_from_errno(int err)
{
	if (WARN_ON(err > 0) || err == 0)
		return 0;
	else
		return ((-err) << SSAM_NOTIF_STATE_SHIFT) | SSAM_NOTIF_STOP;
}

/**
 * ssam_notifier_to_errno() - Convert notifier return code to standard error
 * value.
 * @ret: The notifier return value to convert.
 *
 * Return: Returns the negative error value encoded in @ret or zero if @ret
 * indicates success.
 */
static inline int ssam_notifier_to_errno(u32 ret)
{
	return -(ret >> SSAM_NOTIF_STATE_SHIFT);
}


/* -- Event/notification registry. ------------------------------------------ */

/**
 * struct ssam_event_registry - Registry specification used for enabling events.
 * @target_category: Target category for the event registry requests.
 * @target_id:       Target ID for the event registry requests.
 * @cid_enable:      Command ID for the event-enable request.
 * @cid_disable:     Command ID for the event-disable request.
 *
 * This struct describes a SAM event registry via the minimal collection of
 * SAM IDs specifying the requests to use for enabling and disabling an event.
 * The individual event to be enabled/disabled itself is specified via &struct
 * ssam_event_id.
 */
struct ssam_event_registry {
	u8 target_category;
	u8 target_id;
	u8 cid_enable;
	u8 cid_disable;
};

/**
 * struct ssam_event_id - Unique event ID used for enabling events.
 * @target_category: Target category of the event source.
 * @instance:        Instance ID of the event source.
 *
 * This struct specifies the event to be enabled/disabled via an externally
 * provided registry. It does not specify the registry to be used itself, this
 * is done via &struct ssam_event_registry.
 */
struct ssam_event_id {
	u8 target_category;
	u8 instance;
};

/**
 * enum ssam_event_mask - Flags specifying how events are matched to notifiers.
 *
 * @SSAM_EVENT_MASK_NONE:
 *	Run the callback for any event with matching target category. Do not
 *	do any additional filtering.
 *
 * @SSAM_EVENT_MASK_TARGET:
 *	In addition to filtering by target category, only execute the notifier
 *	callback for events with a target ID matching to the one of the
 *	registry used for enabling/disabling the event.
 *
 * @SSAM_EVENT_MASK_INSTANCE:
 *	In addition to filtering by target category, only execute the notifier
 *	callback for events with an instance ID matching to the instance ID
 *	used when enabling the event.
 *
 * @SSAM_EVENT_MASK_STRICT:
 *	Do all the filtering above.
 */
enum ssam_event_mask {
	SSAM_EVENT_MASK_TARGET   = BIT(0),
	SSAM_EVENT_MASK_INSTANCE = BIT(1),

	SSAM_EVENT_MASK_NONE = 0,
	SSAM_EVENT_MASK_STRICT
		= SSAM_EVENT_MASK_TARGET
		| SSAM_EVENT_MASK_INSTANCE,
};


/**
 * SSAM_EVENT_REGISTRY() - Define a new event registry.
 * @tc:      Target category for the event registry requests.
 * @tid:     Target ID for the event registry requests.
 * @cid_en:  Command ID for the event-enable request.
 * @cid_dis: Command ID for the event-disable request.
 *
 * Return: Returns the &struct ssam_event_registry specified by the given
 * parameters.
 */
#define SSAM_EVENT_REGISTRY(tc, tid, cid_en, cid_dis)	\
	((struct ssam_event_registry) {			\
		.target_category = (tc),		\
		.target_id = (tid),			\
		.cid_enable = (cid_en),			\
		.cid_disable = (cid_dis),		\
	})

#define SSAM_EVENT_REGISTRY_SAM	\
	SSAM_EVENT_REGISTRY(SSAM_SSH_TC_SAM, 0x01, 0x0b, 0x0c)

#define SSAM_EVENT_REGISTRY_KIP	\
	SSAM_EVENT_REGISTRY(SSAM_SSH_TC_KIP, 0x02, 0x27, 0x28)

#define SSAM_EVENT_REGISTRY_REG \
	SSAM_EVENT_REGISTRY(SSAM_SSH_TC_REG, 0x02, 0x01, 0x02)


/**
 * struct ssam_event_notifier - Notifier block for SSAM events.
 * @base:        The base notifier block with callback function and priority.
 * @event:       The event for which this block will receive notifications.
 * @event.reg:   Registry via which the event will be enabled/disabled.
 * @event.id:    ID specifying the event.
 * @event.mask:  Flags determining how events are matched to the notifier.
 * @event.flags: Flags used for enabling the event.
 */
struct ssam_event_notifier {
	struct ssam_notifier_block base;

	struct {
		struct ssam_event_registry reg;
		struct ssam_event_id id;
		enum ssam_event_mask mask;
		u8 flags;
	} event;
};

int ssam_notifier_register(struct ssam_controller *ctrl,
			   struct ssam_event_notifier *n);

int ssam_notifier_unregister(struct ssam_controller *ctrl,
			     struct ssam_event_notifier *n);


/* -- Surface System Aggregator Module Bus. --------------------------------- */

/**
 * struct ssam_device_uid - Unique identifier for SSAM device.
 * @category: Target category of the device.
 * @target:   Target ID of the device.
 * @instance: Instance ID of the device.
 * @function: Sub-function of the device. This field can be used to split a
 *            single SAM device into multiple virtual subdevices to separate
 *            different functionality of that device and allow one driver per
 *            such functionality.
 */
struct ssam_device_uid {
	u8 category;
	u8 target;
	u8 instance;
	u8 function;
};

/**
 * SSAM_DUID() - Define a &struct ssam_device_uid.
 * @cat: Target category of the device.
 * @tid: Target ID of the device.
 * @iid: Instance ID of the device.
 * @fun: Sub-function of the (virtual) device.
 *
 * Return: The &struct ssam_device_uid specified by the given parameters.
 */
#define SSAM_DUID(cat, tid, iid, fun)		\
	((struct ssam_device_uid) {		\
		.category = SSAM_SSH_TC_##cat,	\
		.target = (tid),		\
		.instance = (iid),		\
		.function = (fun)		\
	})

/*
 * SSAM_DUID_NULL - Null device UID.
 */
#define SSAM_DUID_NULL		((struct ssam_device_uid) { 0 })

/*
 * Special values for device matching.
 */
#define SSAM_ANY_TID		0xffff
#define SSAM_ANY_IID		0xffff
#define SSAM_ANY_FUN		0xffff

/**
 * SSAM_DEVICE() - Initialize a &struct ssam_device_id with the given
 * parameters.
 * @cat: Target category of the device.
 * @tid: Target ID of the device.
 * @iid: Instance ID of the device.
 * @fun: Sub-function of the device.
 *
 * Initializes a &struct ssam_device_id with the given parameters. See &struct
 * ssam_device_uid for details regarding the parameters. The special values
 * %SSAM_ANY_TID, %SSAM_ANY_IID, and %SSAM_ANY_FUN can be used to specify that
 * matching should ignore target ID, instance ID, and/or sub-function,
 * respectively. This macro initializes the ``match_flags`` field based on the
 * given parameters.
 */
#define SSAM_DEVICE(cat, tid, iid, fun)						\
	.match_flags = (((tid) != SSAM_ANY_TID) ? SSAM_MATCH_TARGET : 0)	\
		     | (((iid) != SSAM_ANY_IID) ? SSAM_MATCH_INSTANCE : 0)	\
		     | (((fun) != SSAM_ANY_FUN) ? SSAM_MATCH_FUNCTION : 0),	\
	.category = SSAM_SSH_TC_##cat,						\
	.target   = ((tid) != SSAM_ANY_TID) ? (tid) : 0,			\
	.instance = ((iid) != SSAM_ANY_IID) ? (iid) : 0,			\
	.function = ((fun) != SSAM_ANY_FUN) ? (fun) : 0				\


/**
 * ssam_device_uid_equal() - Compare SSAM device UIDs for equality.
 * @u1: The first UID.
 * @u2: The second UID.
 *
 * Return: Returns %true iff both UIDs are equal, %false otherwise.
 */
static inline bool ssam_device_uid_equal(const struct ssam_device_uid u1,
					 const struct ssam_device_uid u2)
{
	return memcmp(&u1, &u2, sizeof(struct ssam_device_uid)) == 0;
}

/**
 * ssam_device_uid_is_null() - Check if a SSAM device UID is null.
 * @uid: The UID to check.
 *
 * Return: Returns %true iff the given UID is null, %false otherwise.
 */
static inline bool ssam_device_uid_is_null(const struct ssam_device_uid uid)
{
	return ssam_device_uid_equal(uid, (struct ssam_device_uid){});
}


/**
 * struct ssam_device - SSAM client device.
 * @dev:  Driver model representation of the device.
 * @ctrl: SSAM controller managing this device.
 * @uid:  UID identifying the device.
 */
struct ssam_device {
	struct device dev;
	struct ssam_controller *ctrl;

	struct ssam_device_uid uid;
};

/**
 * struct ssam_device_driver - SSAM client device driver.
 * @driver:      Base driver model structure.
 * @match_table: Match table specifying which devices the driver should bind to.
 * @probe:       Called when the driver is being bound to a device.
 * @remove:      Called when the driver is being unbound from the device.
 */
struct ssam_device_driver {
	struct device_driver driver;

	const struct ssam_device_id *match_table;

	int  (*probe)(struct ssam_device *sdev);
	void (*remove)(struct ssam_device *sdev);
};

extern struct bus_type ssam_bus_type;
extern const struct device_type ssam_device_type;


/**
 * is_ssam_device() - Check if the given device is a SSAM client device.
 * @d: The device to test the type of.
 *
 * Return: Returns %true iff the specified device is of type &struct
 * ssam_device, i.e. the device type points to %ssam_device_type, and %false
 * otherwise.
 */
static inline bool is_ssam_device(struct device *d)
{
	return d->type == &ssam_device_type;
}

/**
 * to_ssam_device() - Casts the given device to a SSAM client device.
 * @d: The device to cast.
 *
 * Casts the given &struct device to a &struct ssam_device. The caller has to
 * ensure that the given device is actually enclosed in a &struct ssam_device,
 * e.g. by calling is_ssam_device().
 *
 * Return: Returns a pointer to the &struct ssam_device wrapping the given
 * device @d.
 */
static inline struct ssam_device *to_ssam_device(struct device *d)
{
	return container_of(d, struct ssam_device, dev);
}

/**
 * to_ssam_device_driver() - Casts the given device driver to a SSAM client
 * device driver.
 * @d: The driver to cast.
 *
 * Casts the given &struct device_driver to a &struct ssam_device_driver. The
 * caller has to ensure that the given driver is actually enclosed in a
 * &struct ssam_device_driver.
 *
 * Return: Returns the pointer to the &struct ssam_device_driver wrapping the
 * given device driver @d.
 */
static inline
struct ssam_device_driver *to_ssam_device_driver(struct device_driver *d)
{
	return container_of(d, struct ssam_device_driver, driver);
}


const struct ssam_device_id *ssam_device_id_match(
		const struct ssam_device_id *table,
		const struct ssam_device_uid uid);

const struct ssam_device_id *ssam_device_get_match(
		const struct ssam_device *dev);

const void *ssam_device_get_match_data(const struct ssam_device *dev);

struct ssam_device *ssam_device_alloc(struct ssam_controller *ctrl,
				      struct ssam_device_uid uid);

int ssam_device_add(struct ssam_device *sdev);
void ssam_device_remove(struct ssam_device *sdev);

/**
 * ssam_device_get() - Increment reference count of SSAM client device.
 * @sdev: The device to increment the reference count of.
 *
 * Increments the reference count of the given SSAM client device by
 * incrementing the reference count of the enclosed &struct device via
 * get_device().
 *
 * See ssam_device_put() for the counter-part of this function.
 *
 * Return: Returns the device provided as input.
 */
static inline struct ssam_device *ssam_device_get(struct ssam_device *sdev)
{
	get_device(&sdev->dev);
	return sdev;
}

/**
 * ssam_device_put() - Decrement reference count of SSAM client device.
 * @sdev: The device to decrement the reference count of.
 *
 * Decrements the reference count of the given SSAM client device by
 * decrementing the reference count of the enclosed &struct device via
 * put_device().
 *
 * See ssam_device_get() for the counter-part of this function.
 */
static inline void ssam_device_put(struct ssam_device *sdev)
{
	put_device(&sdev->dev);
}

/**
 * ssam_device_get_drvdata() - Get driver-data of SSAM client device.
 * @sdev: The device to get the driver-data from.
 *
 * Return: Returns the driver-data of the given device, previously set via
 * ssam_device_set_drvdata().
 */
static inline void *ssam_device_get_drvdata(struct ssam_device *sdev)
{
	return dev_get_drvdata(&sdev->dev);
}

/**
 * ssam_device_set_drvdata() - Set driver-data of SSAM client device.
 * @sdev: The device to set the driver-data of.
 * @data: The data to set the device's driver-data pointer to.
 */
static inline void ssam_device_set_drvdata(struct ssam_device *sdev, void *data)
{
	dev_set_drvdata(&sdev->dev, data);
}


int __ssam_device_driver_register(struct ssam_device_driver *d, struct module *o);
void ssam_device_driver_unregister(struct ssam_device_driver *d);

/**
 * ssam_device_driver_register() - Register a SSAM client device driver.
 * @drv: The driver to register.
 */
#define ssam_device_driver_register(drv) \
	__ssam_device_driver_register(drv, THIS_MODULE)

/**
 * module_ssam_device_driver() - Helper macro for SSAM device driver
 * registration.
 * @drv: The driver managed by this module.
 *
 * Helper macro to register a SSAM device driver via module_init() and
 * module_exit(). This macro may only be used once per module and replaces
 * the afforementioned definitions.
 */
#define module_ssam_device_driver(drv)			\
	module_driver(drv, ssam_device_driver_register,	\
		      ssam_device_driver_unregister)


/* -- Helpers for client-device requests. ----------------------------------- */

/**
 * SSAM_DEFINE_SYNC_REQUEST_CL_N() - Define synchronous client-device SAM
 * request function with neither argument nor return value.
 * @name: Name of the generated function.
 * @spec: Specification (&struct ssam_request_spec_md) defining the request.
 *
 * Defines a function executing the synchronous SAM request specified by
 * @spec, with the request having neither argument nor return value. Device
 * specifying parameters are not hard-coded, but instead are provided via the
 * client device, specifically its UID, supplied when calling this function.
 * The generated function takes care of setting up the request struct, buffer
 * allocation, as well as execution of the request itself, returning once the
 * request has been fully completed. The required transport buffer will be
 * allocated on the stack.
 *
 * The generated function is defined as ``int name(struct ssam_device *sdev)``,
 * returning the status of the request, which is zero on success and negative
 * on failure. The ``sdev`` parameter specifies both the target device of the
 * request and by association the controller via which the request is sent.
 *
 * Refer to ssam_request_sync_onstack() for more details on the behavior of
 * the generated function.
 */
#define SSAM_DEFINE_SYNC_REQUEST_CL_N(name, spec...)			\
	SSAM_DEFINE_SYNC_REQUEST_MD_N(__raw_##name, spec)		\
	int name(struct ssam_device *sdev)				\
	{								\
		return __raw_##name(sdev->ctrl, sdev->uid.target,	\
				    sdev->uid.instance);		\
	}

/**
 * SSAM_DEFINE_SYNC_REQUEST_CL_W() - Define synchronous client-device SAM
 * request function with argument.
 * @name:  Name of the generated function.
 * @atype: Type of the request's argument.
 * @spec:  Specification (&struct ssam_request_spec_md) defining the request.
 *
 * Defines a function executing the synchronous SAM request specified by
 * @spec, with the request taking an argument of type @atype and having no
 * return value. Device specifying parameters are not hard-coded, but instead
 * are provided via the client device, specifically its UID, supplied when
 * calling this function. The generated function takes care of setting up the
 * request struct, buffer allocation, as well as execution of the request
 * itself, returning once the request has been fully completed. The required
 * transport buffer will be allocated on the stack.
 *
 * The generated function is defined as ``int name(struct ssam_device *sdev,
 * const atype *arg)``, returning the status of the request, which is zero on
 * success and negative on failure. The ``sdev`` parameter specifies both the
 * target device of the request and by association the controller via which
 * the request is sent. The request's argument is specified via the ``arg``
 * pointer.
 *
 * Refer to ssam_request_sync_onstack() for more details on the behavior of
 * the generated function.
 */
#define SSAM_DEFINE_SYNC_REQUEST_CL_W(name, atype, spec...)		\
	SSAM_DEFINE_SYNC_REQUEST_MD_W(__raw_##name, atype, spec)	\
	int name(struct ssam_device *sdev, const atype *arg)		\
	{								\
		return __raw_##name(sdev->ctrl, sdev->uid.target,	\
				    sdev->uid.instance, arg);		\
	}

/**
 * SSAM_DEFINE_SYNC_REQUEST_CL_R() - Define synchronous client-device SAM
 * request function with return value.
 * @name:  Name of the generated function.
 * @rtype: Type of the request's return value.
 * @spec:  Specification (&struct ssam_request_spec_md) defining the request.
 *
 * Defines a function executing the synchronous SAM request specified by
 * @spec, with the request taking no argument but having a return value of
 * type @rtype. Device specifying parameters are not hard-coded, but instead
 * are provided via the client device, specifically its UID, supplied when
 * calling this function. The generated function takes care of setting up the
 * request struct, buffer allocation, as well as execution of the request
 * itself, returning once the request has been fully completed. The required
 * transport buffer will be allocated on the stack.
 *
 * The generated function is defined as ``int name(struct ssam_device *sdev,
 * rtype *ret)``, returning the status of the request, which is zero on
 * success and negative on failure. The ``sdev`` parameter specifies both the
 * target device of the request and by association the controller via which
 * the request is sent. The request's return value is written to the memory
 * pointed to by the ``ret`` parameter.
 *
 * Refer to ssam_request_sync_onstack() for more details on the behavior of
 * the generated function.
 */
#define SSAM_DEFINE_SYNC_REQUEST_CL_R(name, rtype, spec...)		\
	SSAM_DEFINE_SYNC_REQUEST_MD_R(__raw_##name, rtype, spec)	\
	int name(struct ssam_device *sdev, rtype *ret)			\
	{								\
		return __raw_##name(sdev->ctrl, sdev->uid.target,	\
				    sdev->uid.instance, ret);		\
	}

#endif /* _SURFACE_AGGREGATOR_MODULE_H */
