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

/**
 * struct ssam_span - reference to a buffer region
 * @ptr: pointer to the buffer region
 * @len: length of the buffer region
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

enum ssh_packet_priority {
	SSH_PACKET_PRIORITY_FLUSH = 0,
	SSH_PACKET_PRIORITY_DATA  = 0,
	SSH_PACKET_PRIORITY_NAK   = 1 << 4,
	SSH_PACKET_PRIORITY_ACK   = 2 << 4,
};

#define SSH_PACKET_PRIORITY(base, try) \
	((SSH_PACKET_PRIORITY_##base) | ((try) & 0x0f))

#define ssh_packet_priority_get_try(p) ((p) & 0x0f)


enum ssh_packet_flags {
	SSH_PACKET_SF_LOCKED_BIT,
	SSH_PACKET_SF_QUEUED_BIT,
	SSH_PACKET_SF_PENDING_BIT,
	SSH_PACKET_SF_TRANSMITTING_BIT,
	SSH_PACKET_SF_TRANSMITTED_BIT,
	SSH_PACKET_SF_ACKED_BIT,
	SSH_PACKET_SF_CANCELED_BIT,
	SSH_PACKET_SF_COMPLETED_BIT,

	SSH_PACKET_TY_FLUSH_BIT,
	SSH_PACKET_TY_SEQUENCED_BIT,
	SSH_PACKET_TY_BLOCKING_BIT,

	SSH_PACKET_FLAGS_SF_MASK =
		  BIT(SSH_PACKET_SF_LOCKED_BIT)
		| BIT(SSH_PACKET_SF_QUEUED_BIT)
		| BIT(SSH_PACKET_SF_PENDING_BIT)
		| BIT(SSH_PACKET_SF_TRANSMITTING_BIT)
		| BIT(SSH_PACKET_SF_TRANSMITTED_BIT)
		| BIT(SSH_PACKET_SF_ACKED_BIT)
		| BIT(SSH_PACKET_SF_CANCELED_BIT)
		| BIT(SSH_PACKET_SF_COMPLETED_BIT),

	SSH_PACKET_FLAGS_TY_MASK =
		  BIT(SSH_PACKET_TY_FLUSH_BIT)
		| BIT(SSH_PACKET_TY_SEQUENCED_BIT)
		| BIT(SSH_PACKET_TY_BLOCKING_BIT),
};


struct ssh_ptl;
struct ssh_packet;

struct ssh_packet_ops {
	void (*release)(struct ssh_packet *p);
	void (*complete)(struct ssh_packet *p, int status);
};

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

#define to_ssh_packet(ptr, member) \
	container_of(ptr, struct ssh_packet, member)


static inline struct ssh_packet *ssh_packet_get(struct ssh_packet *packet)
{
	kref_get(&packet->refcnt);
	return packet;
}

void ssh_packet_put(struct ssh_packet *p);

static inline void ssh_packet_set_data(struct ssh_packet *p, u8 *ptr, size_t len)
{
	p->data.ptr = ptr;
	p->data.len = len;
}


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
			 const struct ssam_span *data, int status);
};

struct ssh_request {
	struct ssh_packet packet;
	struct list_head node;

	unsigned long state;
	ktime_t timestamp;

	const struct ssh_request_ops *ops;
};

#define to_ssh_request(ptr, member) \
	container_of(ptr, struct ssh_request, member)


static inline struct ssh_request *ssh_request_get(struct ssh_request *r)
{
	ssh_packet_get(&r->packet);
	return r;
}

static inline void ssh_request_put(struct ssh_request *r)
{
	ssh_packet_put(&r->packet);
}

static inline void ssh_request_set_data(struct ssh_request *r, u8 *ptr, size_t len)
{
	ssh_packet_set_data(&r->packet, ptr, len);
}


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

	SSAM_SSH_TC__HUB = 0x00, // not an actual ID, used in for hubs
};

struct ssam_controller;

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
	const u8 *payload;
};

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

struct ssam_request_sync {
	struct ssh_request base;
	struct completion comp;
	struct ssam_response *resp;
	int status;
};

int ssam_request_sync_alloc(size_t payload_len, gfp_t flags,
			    struct ssam_request_sync **rqst,
			    struct ssam_span *buffer);

void ssam_request_sync_init(struct ssam_request_sync *rqst,
			    enum ssam_request_flags flags);

static inline void ssam_request_sync_set_data(struct ssam_request_sync *rqst,
					      u8 *ptr, size_t len)
{
	ssh_request_set_data(&rqst->base, ptr, len);
}

static inline void ssam_request_sync_set_resp(struct ssam_request_sync *rqst,
					      struct ssam_response *resp)
{
	rqst->resp = resp;
}

int ssam_request_sync_submit(struct ssam_controller *ctrl,
			     struct ssam_request_sync *rqst);

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


#define ssam_request_sync_onstack(ctrl, rqst, rsp, payload_len)			\
	({									\
		u8 __data[SSH_COMMAND_MESSAGE_LENGTH(payload_len)];		\
		struct ssam_span __buf = { &__data[0], ARRAY_SIZE(__data) };	\
		int __status;							\
										\
		/* ensure input does not overflow buffer */			\
		if ((rqst)->length <= payload_len) {				\
			__status = ssam_request_sync_with_buffer(		\
					ctrl, rqst, rsp, &__buf);		\
		} else {							\
			__status = -EINVAL;					\
		}								\
										\
		__status;							\
	})


struct ssam_request_spec {
	u8 target_category;
	u8 command_id;
	u8 instance_id;
	u8 channel;
	u8 flags;
};

struct ssam_request_spec_md {
	u8 target_category;
	u8 command_id;
	u8 flags;
};

#define SSAM_DEFINE_SYNC_REQUEST_N(name, spec...)				\
	int name(struct ssam_controller *ctrl)					\
	{									\
		struct ssam_request_spec s = (struct ssam_request_spec)spec;	\
		struct ssam_request rqst;					\
										\
		rqst.target_category = s.target_category;			\
		rqst.command_id = s.command_id;					\
		rqst.instance_id = s.instance_id;				\
		rqst.channel = s.channel;					\
		rqst.flags = s.flags;						\
		rqst.length = 0;						\
		rqst.payload = NULL;						\
										\
		return ssam_request_sync_onstack(ctrl, &rqst, NULL, 0);		\
	}

#define SSAM_DEFINE_SYNC_REQUEST_W(name, wtype, spec...)			\
	int name(struct ssam_controller *ctrl, const wtype *in)			\
	{									\
		struct ssam_request_spec s = (struct ssam_request_spec)spec;	\
		struct ssam_request rqst;					\
										\
		rqst.target_category = s.target_category;			\
		rqst.command_id = s.command_id;					\
		rqst.instance_id = s.instance_id;				\
		rqst.channel = s.channel;					\
		rqst.flags = s.flags;						\
		rqst.length = sizeof(wtype);					\
		rqst.payload = (u8 *)in;					\
										\
		return ssam_request_sync_onstack(ctrl, &rqst, NULL,		\
						 sizeof(wtype));		\
	}

#define SSAM_DEFINE_SYNC_REQUEST_R(name, rtype, spec...)			\
	int name(struct ssam_controller *ctrl, rtype *out)			\
	{									\
		struct ssam_request_spec s = (struct ssam_request_spec)spec;	\
		struct ssam_request rqst;					\
		struct ssam_response rsp;					\
		int status;							\
										\
		rqst.target_category = s.target_category;			\
		rqst.command_id = s.command_id;					\
		rqst.instance_id = s.instance_id;				\
		rqst.channel = s.channel;					\
		rqst.flags = s.flags | SSAM_REQUEST_HAS_RESPONSE;		\
		rqst.length = 0;						\
		rqst.payload = NULL;						\
										\
		rsp.capacity = sizeof(rtype);					\
		rsp.length = 0;							\
		rsp.pointer = (u8 *)out;					\
										\
		status = ssam_request_sync_onstack(ctrl, &rqst, &rsp, 0);	\
		if (status)							\
			return status;						\
										\
		if (rsp.length != sizeof(rtype)) {				\
			struct device *dev = ssam_controller_device(ctrl);	\
			dev_err(dev, "rqst: invalid response length, expected %zu, got %zu" \
				" (tc: 0x%02x, cid: 0x%02x)", sizeof(rtype),	\
				rsp.length, rqst.target_category,		\
				rqst.command_id);				\
			return -EIO;						\
		}								\
										\
		return 0;							\
	}

#define SSAM_DEFINE_SYNC_REQUEST_MD_W(name, wtype, spec...)			\
	int name(struct ssam_controller *ctrl, u8 chn, u8 iid, const wtype *in)	\
	{									\
		struct ssam_request_spec_md s					\
			= (struct ssam_request_spec_md)spec;			\
		struct ssam_request rqst;					\
										\
		rqst.target_category = s.target_category;			\
		rqst.command_id = s.command_id;					\
		rqst.instance_id = iid;						\
		rqst.channel = chn;						\
		rqst.flags = s.flags;						\
		rqst.length = sizeof(wtype);					\
		rqst.payload = (u8 *)in;					\
										\
		return ssam_request_sync_onstack(ctrl, &rqst, NULL,		\
						 sizeof(wtype));		\
	}

#define SSAM_DEFINE_SYNC_REQUEST_MD_R(name, rtype, spec...)			\
	int name(struct ssam_controller *ctrl, u8 chn, u8 iid, rtype *out)	\
	{									\
		struct ssam_request_spec_md s					\
			= (struct ssam_request_spec_md)spec;			\
		struct ssam_request rqst;					\
		struct ssam_response rsp;					\
		int status;							\
										\
		rqst.target_category = s.target_category;			\
		rqst.command_id = s.command_id;					\
		rqst.instance_id = iid;						\
		rqst.channel = chn;						\
		rqst.flags = s.flags | SSAM_REQUEST_HAS_RESPONSE;		\
		rqst.length = 0;						\
		rqst.payload = NULL;						\
										\
		rsp.capacity = sizeof(rtype);					\
		rsp.length = 0;							\
		rsp.pointer = (u8 *)out;					\
										\
		status = ssam_request_sync_onstack(ctrl, &rqst, &rsp, 0);	\
		if (status)							\
			return status;						\
										\
		if (rsp.length != sizeof(rtype)) {				\
			struct device *dev = ssam_controller_device(ctrl);	\
			dev_err(dev, "rqst: invalid response length, expected %zu, got %zu" \
				" (tc: 0x%02x, cid: 0x%02x)", sizeof(rtype),	\
				rsp.length, rqst.target_category,		\
				rqst.command_id);				\
			return -EIO;						\
		}								\
										\
		return 0;							\
	}


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
	if (WARN_ON(err > 0) || err == 0)
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
		.target_category = (tc),		\
		.instance = (iid),			\
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

int ssam_notifier_register(struct ssam_controller *ctrl,
			   struct ssam_event_notifier *n);

int ssam_notifier_unregister(struct ssam_controller *ctrl,
			     struct ssam_event_notifier *n);


/* -- Surface System Aggregator Module Bus. --------------------------------- */

struct ssam_device_uid {
	u8 category;
	u8 channel;
	u8 instance;
	u8 function;
};

#define SSAM_DUID(__cat, __chn, __iid, __fun) 		\
	((struct ssam_device_uid) {			\
		.category = SSAM_SSH_TC_##__cat,	\
		.channel = (__chn),			\
		.instance = (__iid),			\
		.function = (__fun)			\
	})

#define SSAM_DUID_NULL		((struct ssam_device_uid) { 0 })

#define SSAM_ANY_CHN		0xffff
#define SSAM_ANY_IID		0xffff
#define SSAM_ANY_FUN		0xffff

#define SSAM_DEVICE(__cat, __chn, __iid, __fun)					\
	.match_flags = (((__chn) != SSAM_ANY_CHN) ? SSAM_MATCH_CHANNEL : 0)	\
		     | (((__iid) != SSAM_ANY_IID) ? SSAM_MATCH_INSTANCE : 0)	\
		     | (((__fun) != SSAM_ANY_FUN) ? SSAM_MATCH_FUNCTION : 0),	\
	.category = SSAM_SSH_TC_##__cat,					\
	.channel = ((__chn) != SSAM_ANY_CHN) ? (__chn) : 0,			\
	.instance = ((__iid) != SSAM_ANY_IID) ? (__iid) : 0,			\
	.function = ((__fun) != SSAM_ANY_FUN) ? (__fun) : 0			\

static inline bool ssam_device_uid_equal(const struct ssam_device_uid u1,
					 const struct ssam_device_uid u2)
{
	return memcmp(&u1, &u2, sizeof(struct ssam_device_uid)) == 0;
}

static inline bool ssam_device_uid_is_null(const struct ssam_device_uid uid)
{
	return ssam_device_uid_equal(uid, (struct ssam_device_uid){});
}


struct ssam_device {
	struct device dev;
	struct ssam_controller *ctrl;

	struct ssam_device_uid uid;
};

struct ssam_device_driver {
	struct device_driver driver;

	const struct ssam_device_id *match_table;

	int  (*probe)(struct ssam_device *);
	void (*remove)(struct ssam_device *);
};

extern struct bus_type ssam_bus_type;
extern const struct device_type ssam_device_type;


static inline bool is_ssam_device(struct device *device)
{
	return device->type == &ssam_device_type;
}

static inline struct ssam_device *to_ssam_device(struct device *d)
{
	return container_of(d, struct ssam_device, dev);
}

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

static inline void ssam_device_get(struct ssam_device *sdev)
{
	get_device(&sdev->dev);
}

static inline void ssam_device_put(struct ssam_device *sdev)
{
	put_device(&sdev->dev);
}

static inline void *ssam_device_get_drvdata(struct ssam_device *sdev)
{
	return dev_get_drvdata(&sdev->dev);
}

static inline void ssam_device_set_drvdata(struct ssam_device *sdev, void *data)
{
	dev_set_drvdata(&sdev->dev, data);
}


int __ssam_device_driver_register(struct ssam_device_driver *d, struct module *o);
void ssam_device_driver_unregister(struct ssam_device_driver *d);

#define ssam_device_driver_register(drv) \
	__ssam_device_driver_register(drv, THIS_MODULE)

#define module_ssam_device_driver(__drv) \
	module_driver(__drv, ssam_device_driver_register, \
		      ssam_device_driver_unregister)


/* -- Helpers for client-device requests. ----------------------------------- */

#define SSAM_DEFINE_SYNC_REQUEST_CL_W(name, wtype, spec...)		\
	SSAM_DEFINE_SYNC_REQUEST_MD_W(__raw_##name, wtype, spec)	\
	int name(struct ssam_device *sdev, const wtype *in)		\
	{								\
		return __raw_##name(sdev->ctrl, sdev->uid.channel,	\
				    sdev->uid.instance, in);		\
	}

#define SSAM_DEFINE_SYNC_REQUEST_CL_R(name, rtype, spec...)		\
	SSAM_DEFINE_SYNC_REQUEST_MD_R(__raw_##name, rtype, spec)	\
	int name(struct ssam_device *sdev, rtype *out)			\
	{								\
		return __raw_##name(sdev->ctrl, sdev->uid.channel,	\
				    sdev->uid.instance, out);		\
	}


static inline bool ssam_event_matches_device(struct ssam_device_uid uid,
					     const struct ssam_event *event)
{
	return uid.category == event->target_category
		&& uid.channel == event->channel
		&& uid.instance == event->instance_id;
}

#endif /* _SURFACE_AGGREGATOR_MODULE_H */
