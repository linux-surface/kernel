#ifndef _SURFACE_SAM_SID_POWER_H
#define _SURFACE_SAM_SID_POWER_H

#include <linux/types.h>
#include "surface_sam_ssh.h"


struct ssam_battery_properties {
	struct ssam_event_registry registry;
	u8 num;
	u8 channel;
	u8 instance;
};

#endif /* _SURFACE_SAM_SID_POWER_H */
