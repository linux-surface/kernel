#include <linux/firmware.h>
#include <linux/intel_ipts_fw.h>
#include <linux/intel_ipts_if.h>
#include <linux/mutex.h>

#include "ipts.h"
#include "ipts-fw.h"
#include "ipts-params.h"

#define IPTS_GENERIC_FW_PATH_FMT "intel/ipts/%s"

/*
 * This function pointer allows a companion driver to register a custom logic
 * for loading firmware files. This can be used to detect devices that can
 * be used for IPTS versioning, but that are not connected over the MEI bus,
 * and cannot be detected by the ME driver.
 */
IPTS_FW_HANDLER(ipts_fw_handler);
DEFINE_MUTEX(ipts_fw_handler_lock);
void *ipts_fw_handler_data = NULL;

bool ipts_fw_handler_available(void)
{
	bool ret;
	mutex_lock(&ipts_fw_handler_lock);

	ret = ipts_fw_handler != NULL;

	mutex_unlock(&ipts_fw_handler_lock);
	return ret;
}

int intel_ipts_add_fw_handler(IPTS_FW_HANDLER(handler), void *data)
{
	int ret = 0;
	mutex_lock(&ipts_fw_handler_lock);

	if (ipts_fw_handler != NULL) {
		ret = -EBUSY;
		goto ipts_add_fw_handler_return;
	}

	ipts_fw_handler = handler;
	ipts_fw_handler_data = data;

ipts_add_fw_handler_return:

	mutex_unlock(&ipts_fw_handler_lock);
	return ret;
}
EXPORT_SYMBOL(intel_ipts_add_fw_handler);

int intel_ipts_rm_fw_handler(IPTS_FW_HANDLER(handler))
{
	int ret = 0;
	mutex_lock(&ipts_fw_handler_lock);

	if (ipts_fw_handler == NULL) {
		ret = 0;
		goto ipts_rm_fw_handler_return;
	}

	if (*handler != *ipts_fw_handler) {
		ret = -EPERM;
		goto ipts_rm_fw_handler_return;
	}

	ipts_fw_handler = NULL;
	ipts_fw_handler_data = NULL;

ipts_rm_fw_handler_return:

	mutex_unlock(&ipts_fw_handler_lock);
	return ret;
}
EXPORT_SYMBOL(intel_ipts_rm_fw_handler);

int ipts_request_firmware(const struct firmware **fw, const char *name,
	struct device *device)
{
	int ret = 0;
	char fw_path[MAX_IOCL_FILE_PATH_LEN];
	mutex_lock(&ipts_fw_handler_lock);

	// Check if a firmware handler was registered. If not, skip
	// forward and try to load the firmware from the legacy path
	if (ipts_fw_handler == NULL || ipts_modparams.ignore_companion) {
		goto ipts_request_firmware_fallback;
	}

	ret = (*ipts_fw_handler)(fw, name, device, ipts_fw_handler_data);
	if (!ret) {
		goto ipts_request_firmware_return;
	}

ipts_request_firmware_fallback:

	// If fallback loading for firmware was disabled, abort.
	// Return -ENOENT as no firmware file was found.
	if (ipts_modparams.ignore_fw_fallback) {
		ret = -ENOENT;
		goto ipts_request_firmware_return;
	}

	// No firmware was found by the companion driver, try the generic path now.
	snprintf(fw_path, MAX_IOCL_FILE_PATH_LEN, IPTS_GENERIC_FW_PATH_FMT, name);
	ret = request_firmware(fw, fw_path, device);

ipts_request_firmware_return:

	mutex_unlock(&ipts_fw_handler_lock);
	return ret;
}
