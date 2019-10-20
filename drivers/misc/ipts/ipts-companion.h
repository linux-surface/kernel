#ifndef _IPTS_COMPANION_H_
#define _IPTS_COMPANION_H_

#include <linux/firmware.h>

bool ipts_companion_available(void);
int ipts_request_firmware(const struct firmware **fw, const char *name,
		struct device *device);

#endif // _IPTS_COMPANION_H_
