/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Interface for Surface ACPI/Notify (SAN).
 *
 * The SAN is the main interface between the Surface Serial Hub (SSH) and the
 * Surface/System Aggregator Module (SAM). It allows requests to be translated
 * from ACPI to SSH/SAM. It also interfaces with the discrete GPU hot-plug
 * driver.
 */

#ifndef _SURFACE_SAM_SAN_H
#define _SURFACE_SAM_SAN_H

#include <linux/types.h>


struct ssam_anf_dgpu_event {
	u8 category;			// target category
	u8 target;			// target ID
	u8 command;			// command ID
	u8 instance;			// instance ID
	u16 length;			// command data length (length of payload)
	u8 *payload;			// pointer to payload of length cdl
};

int ssam_anf_client_link(struct device *client);
int ssam_anf_dgpu_notifier_register(struct notifier_block *nb);
int ssam_anf_dgpu_notifier_unregister(struct notifier_block *nb);

#endif /* _SURFACE_SAM_SAN_H */
