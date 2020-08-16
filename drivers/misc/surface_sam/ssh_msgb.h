/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _SSAM_SSH_MSGB_H
#define _SSAM_SSH_MSGB_H

#include <asm/unaligned.h>
#include <linux/types.h>

#include <linux/surface_aggregator_module.h>
#include "ssh_protocol.h"


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

#endif /* _SSAM_SSH_MSGB_H */
