/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _SSAM_SSH_PROTOCOL_H
#define _SSAM_SSH_PROTOCOL_H

#include <asm/unaligned.h>
#include <linux/types.h>
#include <linux/crc-ccitt.h>


/*
 * SSH_NUM_EVENTS - The number of reserved event IDs.
 *
 * The number of reserved event IDs, used for registering an SSH event
 * handler. Valid event IDs are numbers below or equal to this value, with
 * exception of zero, which is not an event ID. Thus, this is also the
 * absolute maximum number of event handlers that can be registered.
 */
#define SSH_NUM_EVENTS		34

/*
 * SSH_NUM_TARGETS - The number of communication targets used in the protocol.
 */
#define SSH_NUM_TARGETS		2

/*
 * SSH_MSG_SYN - SSH message synchronization (SYN) bytes as u16.
 */
#define SSH_MSG_SYN		((u16)0x55aa)


/**
 * ssh_crc() - Compute CRC for SSH messages.
 * @buf: The pointer pointing to the data for which the CRC should be computed.
 * @len: The length of the data for which the CRC should be computed.
 *
 * Return: Returns the CRC computed on the provided data, as used for SSH
 * messages.
 */
static inline u16 ssh_crc(const u8 *buf, size_t len)
{
	return crc_ccitt_false(0xffff, buf, len);
}

/**
 * ssh_rqid_next_valid() - Return the next valid request ID.
 * @rqid: The current request ID.
 *
 * Return: Returns the next valid request ID, following the current request ID
 * provided to this function. This function skips any request IDs reserved for
 * events.
 */
static inline u16 ssh_rqid_next_valid(u16 rqid)
{
	return rqid > 0 ? rqid + 1u : rqid + SSH_NUM_EVENTS + 1u;
}

/**
 * ssh_rqid_to_event() - Convert request ID to its corresponding event ID.
 * @rqid: The request ID to convert.
 */
static inline u16 ssh_rqid_to_event(u16 rqid)
{
	return rqid - 1u;
}

/**
 * ssh_rqid_is_event() - Check if given request ID is a valid event ID.
 * @rqid: The request ID to check.
 */
static inline bool ssh_rqid_is_event(u16 rqid)
{
	return ssh_rqid_to_event(rqid) < SSH_NUM_EVENTS;
}

/**
 * ssh_tc_to_rqid() - Convert target category to its corresponding request ID.
 * @tc: The target category to convert.
 */
static inline u16 ssh_tc_to_rqid(u8 tc)
{
	return tc;
}

/**
 * ssh_tid_to_index() - Convert target ID to its corresponding target index.
 * @tid: The target ID to convert.
 */
static inline u8 ssh_tid_to_index(u8 tid)
{
	return tid - 1u;
}

/**
 * ssh_tid_is_valid() - Check if target ID is valid/supported.
 * @tid: The target ID to check.
 */
static inline bool ssh_tid_is_valid(u8 tid)
{
	return ssh_tid_to_index(tid) < SSH_NUM_TARGETS;
}

#endif /* _SSAM_SSH_PROTOCOL_H */
