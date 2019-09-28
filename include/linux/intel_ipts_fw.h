#ifndef _INTEL_IPTS_FW_H_
#define _INTEL_IPTS_FW_H_

#include <linux/firmware.h>

#define MAX_IOCL_FILE_NAME_LEN 80
#define MAX_IOCL_FILE_PATH_LEN 256
#define IPTS_FW_HANDLER(name) int(*name)(const struct firmware **, \
	const char *, struct device *, void *)

int intel_ipts_add_fw_handler(IPTS_FW_HANDLER(handler), void *data);
int intel_ipts_rm_fw_handler(IPTS_FW_HANDLER(handler));

#endif // _INTEL_IPTS_FW_H_
