#include <linux/firmware.h>
#include <linux/ipts.h>
#include <linux/ipts-companion.h>
#include <linux/mutex.h>

#include "ipts.h"
#include "ipts-companion.h"
#include "ipts-params.h"

#define IPTS_FW_PATH_FMT "intel/ipts/%s"

ipts_companion_t *ipts_companion;
DEFINE_MUTEX(ipts_companion_lock);

bool ipts_companion_available(void)
{
	bool ret;
	mutex_lock(&ipts_companion_lock);

	ret = ipts_companion != NULL;

	mutex_unlock(&ipts_companion_lock);
	return ret;
}

/*
 * General purpose API for adding or removing a companion driver
 * A companion driver is a driver that implements hardware specific
 * behaviour into IPTS, so it doesn't have to be hardcoded into the
 * main driver. All requests to the companion driver should be wrapped,
 * with a fallback in case a companion driver cannot be found.
 */

int ipts_add_companion(ipts_companion_t *companion)
{
	int ret = 0;
	mutex_lock(&ipts_companion_lock);

	if (ipts_companion != NULL) {
		ret = -EBUSY;
		goto add_companion_return;
	}

	ipts_companion = companion;

add_companion_return:

	mutex_unlock(&ipts_companion_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(ipts_add_companion);

int ipts_remove_companion(ipts_companion_t *companion)
{
	int ret = 0;
	mutex_lock(&ipts_companion_lock);

	if (ipts_companion == NULL || companion == NULL) {
		ret = 0;
		goto remove_companion_return;
	}

	if (ipts_companion->name != companion->name) {
		ret = -EPERM;
		goto remove_companion_return;
	}

	ipts_companion = NULL;

remove_companion_return:

	mutex_unlock(&ipts_companion_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(ipts_remove_companion);

/*
 * Utility functions for IPTS. These functions replace codepaths in the IPTS
 * driver, and redirect them to the companion driver, if one was found.
 * Otherwise the legacy code gets executed as a fallback.
 */

int ipts_request_firmware(const struct firmware **fw, const char *name,
	struct device *device)
{
	int ret = 0;
	char fw_path[MAX_IOCL_FILE_PATH_LEN];
	mutex_lock(&ipts_companion_lock);

	// Check if a companion was registered. If not, skip
	// forward and try to load the firmware from the legacy path
	if (ipts_companion == NULL || ipts_modparams.ignore_companion) {
		goto request_firmware_fallback;
	}

	ret = ipts_companion->firmware_request(fw, name, device, ipts_companion);
	if (!ret) {
		goto request_firmware_return;
	}

request_firmware_fallback:

	// If fallback loading for firmware was disabled, abort.
	// Return -ENOENT as no firmware file was found.
	if (ipts_modparams.ignore_fw_fallback) {
		ret = -ENOENT;
		goto request_firmware_return;
	}

	// No firmware was found by the companion driver, try the generic path.
	snprintf(fw_path, MAX_IOCL_FILE_PATH_LEN, IPTS_FW_PATH_FMT, name);
	ret = request_firmware(fw, fw_path, device);

request_firmware_return:

	mutex_unlock(&ipts_companion_lock);
	return ret;
}
