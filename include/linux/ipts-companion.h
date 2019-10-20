#ifndef _INTEL_IPTS_COMPANION_H_
#define _INTEL_IPTS_COMPANION_H_

#include <linux/firmware.h>
#include <linux/ipts-binary.h>

typedef struct ipts_companion ipts_companion_t;

typedef int (*ipts_fw_handler_t)(const struct firmware **, const char *,
		struct device *, ipts_companion_t *companion);

struct ipts_companion {
	ipts_fw_handler_t firmware_request;
	ipts_bin_fw_info_t **firmware_config;
	void *data;
	const char *name;
};

int ipts_add_companion(ipts_companion_t *companion);
int ipts_remove_companion(ipts_companion_t *companion);

#endif // _INTEL_IPTS_COMPANION_H_
