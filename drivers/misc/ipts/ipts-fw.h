#ifndef _IPTS_FW_H_
#define _IPTS_FW_H_

#include <linux/firmware.h>

#include "ipts.h"

int ipts_request_firmware(const struct firmware **fw, const char *name,
	struct device *device);
bool ipts_fw_handler_available(void);

#endif // _IPTS_FW_H_
