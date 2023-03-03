/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM lockd

#if !defined(_TRACE_LOCKD_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_LOCKD_H

#include <linux/tracepoint.h>
#include <linux/crc32.h>
#include <linux/nfs.h>
#include <linux/lockd/lockd.h>

#define show_nlm_status(val)							\
	__print_symbolic(val,							\
		{ NLM_LCK_GRANTED,		"LCK_GRANTED" },		\
		{ NLM_LCK_DENIED,		"LCK_DENIED" },			\
		{ NLM_LCK_DENIED_NOLOCKS,	"LCK_DENIED_NOLOCKS" },		\
		{ NLM_LCK_BLOCKED,		"LCK_BLOCKED" },		\
		{ NLM_LCK_DENIED_GRACE_PERIOD,	"LCK_DENIED_GRACE_PERIOD" },	\
		{ NLM_DEADLCK,			"DEADLCK" },			\
		{ NLM_ROFS,			"ROFS" },			\
		{ NLM_STALE_FH,			"STALE_FH" },			\
		{ NLM_FBIG,			"FBIG" },			\
		{ NLM_FAILED,			"FAILED" })

DECLARE_EVENT_CLASS(nlmclnt_lock_event,
		TP_PROTO(
			const struct nlm_lock *lock,
			const struct sockaddr *addr,
			unsigned int addrlen,
			__be32 status
		),

		TP_ARGS(lock, addr, addrlen, status),

		TP_STRUCT__entry(
			__field(u32, oh)
			__field(u32, svid)
			__field(u32, fh)
			__field(unsigned long, status)
			__field(u64, start)
			__field(u64, len)
			__sockaddr(addr, addrlen)
		),

		TP_fast_assign(
			__entry->oh = ~crc32_le(0xffffffff, lock->oh.data, lock->oh.len);
			__entry->svid = lock->svid;
			__entry->fh = nfs_fhandle_hash(&lock->fh);
			__entry->start = lock->lock_start;
			__entry->len = lock->lock_len;
			__entry->status = be32_to_cpu(status);
			__assign_sockaddr(addr, addr, addrlen);
		),

		TP_printk(
			"addr=%pISpc oh=0x%08x svid=0x%08x fh=0x%08x start=%llu len=%llu status=%s",
			__get_sockaddr(addr), __entry->oh, __entry->svid,
			__entry->fh, __entry->start, __entry->len,
			show_nlm_status(__entry->status)
		)
);

#define DEFINE_NLMCLNT_EVENT(name)				\
	DEFINE_EVENT(nlmclnt_lock_event, name,			\
			TP_PROTO(				\
				const struct nlm_lock *lock,	\
				const struct sockaddr *addr,	\
				unsigned int addrlen,		\
				__be32	status			\
			),					\
			TP_ARGS(lock, addr, addrlen, status))

DEFINE_NLMCLNT_EVENT(nlmclnt_test);
DEFINE_NLMCLNT_EVENT(nlmclnt_lock);
DEFINE_NLMCLNT_EVENT(nlmclnt_unlock);
DEFINE_NLMCLNT_EVENT(nlmclnt_grant);

#endif /* _TRACE_LOCKD_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE trace
#include <trace/define_trace.h>
