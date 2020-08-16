/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _SSAM_BUS_H
#define _SSAM_BUS_H

#include <linux/surface_aggregator_module.h>


void ssam_controller_remove_clients(struct ssam_controller *ctrl);

int ssam_bus_register(void);
void ssam_bus_unregister(void);

#endif /* _SSAM_BUS_H */
