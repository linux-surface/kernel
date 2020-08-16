/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _SSAM_SSH_PROTOCOL_H
#define _SSAM_SSH_PROTOCOL_H

#include <asm/unaligned.h>
#include <linux/types.h>
#include <linux/crc-ccitt.h>


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

/**
 * SSH message syncrhonization (SYN) bytes.
 */
#define SSH_MSG_SYN		((u16)0x55aa)


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

#endif /* _SSAM_SSH_PROTOCOL_H */
