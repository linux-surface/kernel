/*
 * Interface for Surface Serial Hub (SSH).
 *
 * The SSH is the main communication hub for communication between host and
 * the Surface/System Aggregator Module (SAM) on newer Microsoft Surface
 * devices (Book 2, Pro 5, Laptops, ...). Also referred to as SAM-over-SSH.
 * Older devices (Book 1, Pro 4) use SAM-over-I2C.
 */

#ifndef _SURFACE_SAM_SSH_H
#define _SURFACE_SAM_SSH_H

#include <linux/types.h>
#include <linux/device.h>


/*
 * Maximum request payload size in bytes.
 * Value based on ACPI (255 bytes minus header/status bytes).
 */
#define SURFACE_SAM_SSH_MAX_RQST_PAYLOAD	(255 - 10)

/*
 * Maximum response payload size in bytes.
 * Value based on ACPI (255 bytes minus header/status bytes).
 */
#define SURFACE_SAM_SSH_MAX_RQST_RESPONSE	(255 - 4)

/*
 * The number of (lower) bits of the request ID (RQID) reserved for events.
 * These bits may only be used exclusively for events sent from the EC to the
 * host.
 */
#define SURFACE_SAM_SSH_RQID_EVENT_BITS		5

/*
 * Special event-handler delay value indicating that the corresponding event
 * should be handled immediately in the interrupt and not be relayed through
 * the workqueue. Intended for low-latency events, such as keyboard events.
 */
#define SURFACE_SAM_SSH_EVENT_IMMEDIATE		((unsigned long) -1)


struct surface_sam_ssh_buf {
	u8 cap;
	u8 len;
	u8 *data;
};

struct surface_sam_ssh_rqst {
	u8 tc;
	u8 iid;
	u8 cid;
	u8 snc;
	u8 cdl;
	u8 *pld;
};

struct surface_sam_ssh_event {
	u16 rqid;
	u8  tc;
	u8  iid;
	u8  cid;
	u8  len;
	u8 *pld;
};


typedef int (*surface_sam_ssh_event_handler_fn)(struct surface_sam_ssh_event *event, void *data);
typedef unsigned long (*surface_sam_ssh_event_handler_delay)(struct surface_sam_ssh_event *event, void *data);

int surface_sam_ssh_consumer_register(struct device *consumer);

int surface_sam_ssh_rqst(const struct surface_sam_ssh_rqst *rqst, struct surface_sam_ssh_buf *result);

int surface_sam_ssh_enable_event_source(u8 tc, u8 unknown, u16 rqid);
int surface_sam_ssh_disable_event_source(u8 tc, u8 unknown, u16 rqid);
int surface_sam_ssh_remove_event_handler(u16 rqid);

int surface_sam_ssh_set_delayed_event_handler(u16 rqid,
		surface_sam_ssh_event_handler_fn fn,
		surface_sam_ssh_event_handler_delay delay,
		void *data);

static inline int surface_sam_ssh_set_event_handler(u16 rqid, surface_sam_ssh_event_handler_fn fn, void *data)
{
	return surface_sam_ssh_set_delayed_event_handler(rqid, fn, NULL, data);
}


#endif /* _SURFACE_SAM_SSH_H */
