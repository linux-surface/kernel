#ifndef _SURFACE_SAM_SID_VHF_H
#define _SURFACE_SAM_SID_VHF_H

#include <linux/types.h>
#include "surface_sam_ssh.h"


struct ssam_hid_properties {
	struct ssam_event_registry registry;
	u8 instance;
};

#endif /* _SURFACE_SAM_SID_VHF_H */
