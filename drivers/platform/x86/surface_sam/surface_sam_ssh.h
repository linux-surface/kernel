/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Interface for Surface Serial Hub (SSH).
 *
 * The SSH is the main communication hub for communication between host and
 * the Surface/System Aggregator Module (SAM) on newer Microsoft Surface
 * devices (Book 2, Pro 5, Laptops, ...). Also referred to as SAM-over-SSH.
 * Older devices (Book 1, Pro 4) use SAM-over-HID (via I2C).
 */

#ifndef _SURFACE_SAM_SSH_H
#define _SURFACE_SAM_SSH_H

#include <linux/types.h>
#include <linux/device.h>


/* -- Data structures for SAM-over-SSH communication. ----------------------- */

/**
 * enum ssh_frame_type - Frame types for SSH frames.
 * @SSH_FRAME_TYPE_DATA_SEQ: Indicates a data frame, followed by a payload with
 *                      the length specified in the ssh_frame.len field. This
 *                      frame is sequenced, meaning that an ACK is required.
 * @SSH_FRAME_TYPE_DATA_NSQ: Same as SSH_FRAME_TYPE_DATA_SEQ, but unsequenced,
 *                      meaning that the message does not have to be ACKed.
 * @SSH_FRAME_TYPE_ACK: Indicates an ACK message.
 * @SSH_FRAME_TYPE_NAK: Indicates an error response for previously sent
 *                      frame. In general, this means that the frame and/or
 *                      payload is malformed, e.g. a CRC is wrong. For command-
 *                      type payloads, this can also mean that the command is
 *                      invalid.
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
 * Maximum SSH frame payload length in bytes. This is the physical maximum
 * length of the protocol. Implementations may set a more constrained limit.
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
 * @chn_out: Output channel. Should be zero if this an incoming (EC to host)
 *           message.
 * @chn_in:  Input channel. Should be zero if this is an outgoing (hos to EC)
 *           message.
 * @iid:     Instance ID.
 * @rqid:    Request ID. Used to match requests with responses and differentiate
 *           between responses and events.
 * @cid:     Command ID.
 */
struct ssh_command {
	u8 type;
	u8 tc;
	u8 chn_out;
	u8 chn_in;
	u8 iid;
	__le16 rqid;
	u8 cid;
} __packed;

static_assert(sizeof(struct ssh_command) == 8);

/*
 * Maximum SSH command payload length in bytes. This is the physical maximum
 * length of the protocol. Implementations may set a more constrained limit.
 */
#define SSH_COMMAND_MAX_PAYLOAD_SIZE \
	(SSH_FRAME_MAX_PAYLOAD_SIZE - sizeof(struct ssh_command))

/**
 * struct ssh_notification_params - Command payload to enable/disable SSH
 * notifications.
 * @target_category: The target category for which notifications should be
 *                   enabled/disabled.
 * @flags:           Flags determining how notifications are being sent.
 * @request_id:      The request ID that is used to send these notifications.
 * @instance_id:     The specific instance in the given target category for
 *                   which notifications should be enabled.
 */
struct ssh_notification_params {
	u8 target_category;
	u8 flags;
	__le16 request_id;
	u8 instance_id;
} __packed;

static_assert(sizeof(struct ssh_notification_params) == 5);

/**
 * SSH message syncrhonization (SYN) bytes.
 */
#define SSH_MSG_SYN		((u16)0x55aa)

/**
 * Base-length of a SSH message. This is the minimum number of bytes required
 * to form a message. The actual message length is SSH_MSG_LEN_BASE plus the
 * length of the frame payload.
 */
#define SSH_MSG_LEN_BASE	(sizeof(struct ssh_frame) + 3ull * sizeof(u16))

/**
 * Length of a SSH control message.
 */
#define SSH_MSG_LEN_CTRL	SSH_MSG_LEN_BASE

/**
 * Length of a SSH message with payload of specified size.
 */
#define SSH_MESSAGE_LENGTH(payload_size) (SSH_MSG_LEN_BASE + payload_size)

/**
 * Length of a SSH command message with command payload of specified size.
 */
#define SSH_COMMAND_MESSAGE_LENGTH(payload_size) \
	SSH_MESSAGE_LENGTH(sizeof(struct ssh_command) + payload_size)

/**
 * Offset of the specified struct ssh_frame field in the raw SSH message data.
 */
#define SSH_MSGOFFSET_FRAME(field) \
	(sizeof(u16) + offsetof(struct ssh_frame, field))

/**
 * Offset of the specified struct ssh_command field in the raw SSH message data.
 */
#define SSH_MSGOFFSET_COMMAND(field) \
	(2ull * sizeof(u16) + sizeof(struct ssh_frame) \
		+ offsetof(struct ssh_command, field))

struct sshp_span {
	u8    *ptr;
	size_t len;
};


/* -- Packet transport layer (ptl). ----------------------------------------- */

enum ssh_packet_priority {
	SSH_PACKET_PRIORITY_FLUSH = 0,
	SSH_PACKET_PRIORITY_DATA  = 0,
	SSH_PACKET_PRIORITY_NAK   = 1 << 4,
	SSH_PACKET_PRIORITY_ACK   = 2 << 4,
};

#define SSH_PACKET_PRIORITY(base, try) \
	((SSH_PACKET_PRIORITY_##base) | ((try) & 0x0f))

#define ssh_packet_priority_get_try(p) ((p) & 0x0f)


enum ssh_packet_type_flags {
	SSH_PACKET_TY_FLUSH_BIT,
	SSH_PACKET_TY_SEQUENCED_BIT,
	SSH_PACKET_TY_BLOCKING_BIT,

	SSH_PACKET_TY_FLUSH	= BIT(SSH_PACKET_TY_FLUSH_BIT),
	SSH_PACKET_TY_SEQUENCED	= BIT(SSH_PACKET_TY_SEQUENCED_BIT),
	SSH_PACKET_TY_BLOCKING	= BIT(SSH_PACKET_TY_BLOCKING_BIT),
};

enum ssh_packet_state_flags {
	SSH_PACKET_SF_LOCKED_BIT,
	SSH_PACKET_SF_QUEUED_BIT,
	SSH_PACKET_SF_PENDING_BIT,
	SSH_PACKET_SF_TRANSMITTING_BIT,
	SSH_PACKET_SF_TRANSMITTED_BIT,
	SSH_PACKET_SF_ACKED_BIT,
	SSH_PACKET_SF_CANCELED_BIT,
	SSH_PACKET_SF_COMPLETED_BIT,
};


struct ssh_ptl;
struct ssh_packet;

struct ssh_packet_ops {
	void (*release)(struct ssh_packet *packet);
	void (*complete)(struct ssh_packet *packet, int status);
};

struct ssh_packet {
	struct ssh_ptl *ptl;
	struct kref refcnt;

	u8 type;
	u8 priority;
	u16 data_length;
	u8 *data;

	unsigned long state;
	ktime_t timestamp;

	struct list_head queue_node;
	struct list_head pending_node;

	const struct ssh_packet_ops *ops;
};


/* -- Request transport layer (rtl). ---------------------------------------- */

enum ssh_request_flags {
	SSH_REQUEST_SF_LOCKED_BIT,
	SSH_REQUEST_SF_QUEUED_BIT,
	SSH_REQUEST_SF_PENDING_BIT,
	SSH_REQUEST_SF_TRANSMITTING_BIT,
	SSH_REQUEST_SF_TRANSMITTED_BIT,
	SSH_REQUEST_SF_RSPRCVD_BIT,
	SSH_REQUEST_SF_CANCELED_BIT,
	SSH_REQUEST_SF_COMPLETED_BIT,

	SSH_REQUEST_TY_FLUSH_BIT,
	SSH_REQUEST_TY_HAS_RESPONSE_BIT,

	SSH_REQUEST_FLAGS_SF_MASK =
		  BIT(SSH_REQUEST_SF_LOCKED_BIT)
		| BIT(SSH_REQUEST_SF_QUEUED_BIT)
		| BIT(SSH_REQUEST_SF_PENDING_BIT)
		| BIT(SSH_REQUEST_SF_TRANSMITTING_BIT)
		| BIT(SSH_REQUEST_SF_TRANSMITTED_BIT)
		| BIT(SSH_REQUEST_SF_RSPRCVD_BIT)
		| BIT(SSH_REQUEST_SF_CANCELED_BIT)
		| BIT(SSH_REQUEST_SF_COMPLETED_BIT),

	SSH_REQUEST_FLAGS_TY_MASK =
		  BIT(SSH_REQUEST_TY_FLUSH_BIT)
		| BIT(SSH_REQUEST_TY_HAS_RESPONSE_BIT),
};


struct ssh_rtl;
struct ssh_request;

struct ssh_request_ops {
	void (*release)(struct ssh_request *rqst);
	void (*complete)(struct ssh_request *rqst,
			 const struct ssh_command *cmd,
			 const struct sshp_span *data, int status);
};

struct ssh_request {
	struct ssh_rtl *rtl;
	struct ssh_packet packet;
	struct list_head node;

	unsigned long state;
	ktime_t timestamp;

	const struct ssh_request_ops *ops;
};


/* -- Main data types and definitions --------------------------------------- */

enum ssam_ssh_tc {
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
};

/**
 * struct ssam_event_flags - Flags for enabling/disabling SAM-over-SSH events
 * @SSAM_EVENT_SEQUENCED: The event will be sent via a sequenced data frame.
 */
enum ssam_event_flags {
	SSAM_EVENT_SEQUENCED = BIT(0),
};

struct ssam_event {
	u8 target_category;
	u8 command_id;
	u8 instance_id;
	u8 channel;
	u16 length;
	u8 data[0];
};


/* -- Event notifier/callbacks. --------------------------------------------- */

#define SSAM_NOTIF_STATE_SHIFT		2
#define SSAM_NOTIF_STATE_MASK		((1 << SSAM_NOTIF_STATE_SHIFT) - 1)

#define SSAM_NOTIF_HANDLED		BIT(0)
#define SSAM_NOTIF_STOP			BIT(1)


struct ssam_notifier_block;

typedef u32 (*ssam_notifier_fn_t)(struct ssam_notifier_block *nb,
				  const struct ssam_event *event);

struct ssam_notifier_block {
	struct ssam_notifier_block __rcu *next;
	ssam_notifier_fn_t fn;
	int priority;
};


static inline u32 ssam_notifier_from_errno(int err)
{
	WARN_ON(err > 0);

	if (err >= 0)
		return 0;
	else
		return ((-err) << SSAM_NOTIF_STATE_SHIFT) | SSAM_NOTIF_STOP;
}

static inline int ssam_notifier_to_errno(u32 ret)
{
	return -(ret >> SSAM_NOTIF_STATE_SHIFT);
}


/* -- Event/notification registry. ------------------------------------------ */

struct ssam_event_registry {
	u8 target_category;
	u8 channel;
	u8 cid_enable;
	u8 cid_disable;
};

struct ssam_event_id {
	u8 target_category;
	u8 instance;
};


#define SSAM_EVENT_REGISTRY(tc, chn, cid_en, cid_dis)	\
	((struct ssam_event_registry) {			\
		.target_category = (tc),		\
		.channel = (chn),			\
		.cid_enable = (cid_en),			\
		.cid_disable = (cid_dis),		\
	})

#define SSAM_EVENT_ID(tc, iid)				\
	((struct ssam_event_id) {			\
		.target_category = tc,			\
		.instance = iid,			\
	})


#define SSAM_EVENT_REGISTRY_SAM	\
	SSAM_EVENT_REGISTRY(SSAM_SSH_TC_SAM, 0x01, 0x0b, 0x0c)

#define SSAM_EVENT_REGISTRY_KIP	\
	SSAM_EVENT_REGISTRY(SSAM_SSH_TC_KIP, 0x02, 0x27, 0x28)

#define SSAM_EVENT_REGISTRY_REG \
	SSAM_EVENT_REGISTRY(SSAM_SSH_TC_REG, 0x02, 0x01, 0x02)


struct ssam_event_notifier {
	struct ssam_notifier_block base;

	struct {
		struct ssam_event_registry reg;
		struct ssam_event_id id;
		u8 flags;
	} event;
};


/* -- TODO -------------------------------------------------------------------*/

/*
 * Maximum response payload size in bytes.
 * Value based on ACPI (255 bytes minus header/status bytes).
 */
#define SURFACE_SAM_SSH_MAX_RQST_RESPONSE	(255 - 4)

/*
 * The number of reserved event IDs, used for registering an SSH event
 * handler. Valid event IDs are numbers below or equal to this value, with
 * exception of zero, which is not an event ID. Thus, this is also the
 * absolute maximum number of event handlers that can be registered.
 */
#define SURFACE_SAM_SSH_NUM_EVENTS		0x22

/*
 * The number of communication channels used in the protocol.
 */
#define SURFACE_SAM_SSH_NUM_CHANNELS		2


struct surface_sam_ssh_buf {
	u8 cap;
	u8 len;
	u8 *data;
};

struct surface_sam_ssh_rqst {
	u8 tc;				// target category
	u8 cid;				// command ID
	u8 iid;				// instance ID
	u8 chn;				// channel
	u8 snc;				// expect response flag (bool: 0/1)
	u16 cdl;			// command data length (length of payload)
	u8 *pld;			// pointer to payload of length cdl
};

// TODO: remove rqid on external api
struct surface_sam_ssh_event {
	u16 rqid;			// event type/source ID
	u8  tc;				// target category
	u8  cid;			// command ID
	u8  iid;			// instance ID
	u8  chn;			// channel
	u8  len;			// length of payload
	u8 *pld;			// payload of length len
};


int surface_sam_ssh_consumer_register(struct device *consumer);

int surface_sam_ssh_notifier_register(struct ssam_event_notifier *n);
int surface_sam_ssh_notifier_unregister(struct ssam_event_notifier *n);

int surface_sam_ssh_rqst(const struct surface_sam_ssh_rqst *rqst, struct surface_sam_ssh_buf *result);

#endif /* _SURFACE_SAM_SSH_H */
