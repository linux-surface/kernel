#ifndef _IPTS_COMPANION_H_
#define _IPTS_COMPANION_H_

#include <linux/firmware.h>
#include <linux/ipts-binary.h>

#include "ipts.h"

bool ipts_companion_available(void);
int ipts_request_firmware(const struct firmware **fw, const char *name,
		struct device *device);
int ipts_request_firmware_config(ipts_info_t *ipts,
		ipts_bin_fw_list_t **firmware_config);

#endif // _IPTS_COMPANION_H_
