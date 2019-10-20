#ifndef _INTEL_IPTS_COMPANION_H_
#define _INTEL_IPTS_COMPANION_H_

#include <linux/firmware.h>

typedef struct ipts_companion ipts_companion_t;

typedef int (*ipts_fw_handler_t)(const struct firmware **, const char *,
		struct device *, ipts_companion_t *companion);

struct ipts_companion {
	ipts_fw_handler_t firmware_request;
	void *data;
	const char *name;
};

int ipts_add_companion(ipts_companion_t *companion);
int ipts_remove_companion(ipts_companion_t *companion);

#endif // _INTEL_IPTS_COMPANION_H_
