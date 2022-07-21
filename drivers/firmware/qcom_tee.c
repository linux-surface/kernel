// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Interface driver for the Qualcomm Trusted Execution Environment (TrEE or
 * TEE) / TrustZone secure OS (TzOS). Manages communication via Secure Channel
 * Manager (SCM) calls.
 *
 * Copyright (C) 2022 Maximilian Luz <luzmaximilian@gmail.com>
 */

#include <asm/barrier.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/qcom_scm.h>
#include <linux/string.h>

#include <linux/qcom_tee.h>


/* -- Secure-OS SCM call interface. ----------------------------------------- */

static DEFINE_MUTEX(scm_call_lock);

static int __qctee_os_scm_call(const struct qcom_scm_desc *desc,
			       struct qctee_os_scm_resp *res)
{
	struct qcom_scm_res scm_res = {};
	int status;

	status = qcom_scm_call(desc, &scm_res);

	res->status = scm_res.result[0];
	res->resp_type = scm_res.result[1];
	res->data = scm_res.result[2];

	if (status)
		return status;

	return 0;
}

/**
 * qctee_os_scm_call() - Perform a TrEE SCM call.
 * @dev:  The (client) device to use for logging.
 * @desc: SCM call descriptor.
 * @res:  SCM call response (output).
 *
 * Performs the TrEE SCM call described by @desc, returning the response in
 * @rsp. The provided device @dev is used exclusively for logging.
 *
 * Return: Returns zero on success, nonzero on failure.
 */
int qctee_os_scm_call(struct device *dev, const struct qcom_scm_desc *desc,
		      struct qctee_os_scm_resp *res)
{
	int status;

	/*
	 * Note: Multiple TrEE SCM calls should not be executed same time, so
	 * lock things here. This needs to be extended to callback/listener
	 * handling when support for that is implemented.
	 */

	mutex_lock(&scm_call_lock);
	status = __qctee_os_scm_call(desc, res);
	mutex_unlock(&scm_call_lock);

	dev_dbg(dev, "%s: owner=%x, svc=%x, cmd=%x, status=%lld, type=%llx, data=%llx",
		__func__, desc->owner, desc->svc, desc->cmd, res->status,
		res->resp_type, res->data);

	if (status) {
		dev_err(dev, "qcom_scm_call failed with error %d\n", status);
		return status;
	}

	/*
	 * TODO: Handle incomplete and blocked calls:
	 *
	 * Incomplete and blocked calls are not supported yet. Some devices
	 * and/or commands require those, some don't. Let's warn about them
	 * prominently in case someone attempts to try these commands with a
	 * device/command combination that isn't supported yet.
	 */
	WARN_ON(res->status == QCTEE_OS_RESULT_INCOMPLETE);
	WARN_ON(res->status == QCTEE_OS_RESULT_BLOCKED_ON_LISTENER);

	return 0;
}
EXPORT_SYMBOL_GPL(qctee_os_scm_call);


/* -- Secure App interface. ------------------------------------------------- */

/**
 * qctee_app_get_id() - Query the app ID for a given TrEE app name.
 * @dev:      The (client) device used for logging and DMA mapping.
 * @app_name: The name of the app.
 * @app_id:   The returned app ID.
 *
 * Query and return the application ID of the TrEE app identified by the given
 * name. This returned ID is the unique identifier of the app required for
 * subsequent communication.
 *
 * Return: Returns zero on success, nonzero on failure. Returns -ENOENT if the
 * app has not been loaded or could not be found.
 */
int qctee_app_get_id(struct device *dev, const char *app_name, u32 *app_id)
{
	unsigned long name_buf_size = QCTEE_MAX_APP_NAME_SIZE;
	unsigned long app_name_len = strlen(app_name);
	struct qcom_scm_desc desc = {};
	struct qctee_os_scm_resp res = {};
	dma_addr_t name_buf_phys;
	char *name_buf;
	int status;

	if (app_name_len >= name_buf_size)
		return -EINVAL;

	name_buf = kzalloc(name_buf_size, GFP_KERNEL);
	if (!name_buf)
		return -ENOMEM;

	memcpy(name_buf, app_name, app_name_len);

	name_buf_phys = dma_map_single(dev, name_buf, name_buf_size, DMA_TO_DEVICE);
	if (dma_mapping_error(dev, name_buf_phys)) {
		kfree(name_buf);
		dev_err(dev, "failed to map dma address\n");
		return -EFAULT;
	}

	desc.owner = QCTEE_TZ_OWNER_QSEE_OS;
	desc.svc = QCTEE_TZ_SVC_APP_MGR;
	desc.cmd = 0x03;
	desc.arginfo = QCOM_SCM_ARGS(2, QCOM_SCM_RW, QCOM_SCM_VAL);
	desc.args[0] = name_buf_phys;
	desc.args[1] = app_name_len;

	status = qctee_os_scm_call(dev, &desc, &res);
	dma_unmap_single(dev, name_buf_phys, name_buf_size, DMA_TO_DEVICE);
	kfree(name_buf);

	if (status)
		return status;

	if (res.status != QCTEE_OS_RESULT_SUCCESS)
		return -ENOENT;

	*app_id = res.data;
	return 0;
}
EXPORT_SYMBOL_GPL(qctee_app_get_id);

/**
 * qctee_app_send() - Send to and receive data from a given TrEE app.
 * @dev:    The (client) device used for logging.
 * @app_id: The ID of the app to communicate with.
 * @req:    DMA region of the request sent to the app.
 * @rsp:    DMA region of the response returned by the app.
 *
 * Sends a request to the TrEE app identified by the given ID and read back its
 * response. The caller must provide two DMA memory regions, one for the
 * request and one for the response, and fill out the @req region with the
 * respective (app-specific) request data. The TrEE app reads this and returns
 * its response in the @rsp region.
 *
 * Return: Returns zero on success, nonzero on failure.
 */
int qctee_app_send(struct device *dev, u32 app_id, struct qctee_dma *req, struct qctee_dma *rsp)
{
	struct qctee_os_scm_resp res = {};
	int status;

	struct qcom_scm_desc desc = {
		.owner = QCTEE_TZ_OWNER_TZ_APPS,
		.svc = QCTEE_TZ_SVC_APP_ID_PLACEHOLDER,
		.cmd = 0x01,
		.arginfo = QCOM_SCM_ARGS(5, QCOM_SCM_VAL,
					 QCOM_SCM_RW, QCOM_SCM_VAL,
					 QCOM_SCM_RW, QCOM_SCM_VAL),
		.args[0] = app_id,
		.args[1] = req->phys,
		.args[2] = req->size,
		.args[3] = rsp->phys,
		.args[4] = rsp->size,
	};

	/* Make sure the request is fully written before sending it off. */
	dma_wmb();

	status = qctee_os_scm_call(dev, &desc, &res);

	/* Make sure we don't attempt any reads before the SCM call is done. */
	dma_rmb();

	if (status)
		return status;

	if (res.status != QCTEE_OS_RESULT_SUCCESS)
		return -EIO;

	return 0;
}
EXPORT_SYMBOL_GPL(qctee_app_send);


/* -- Module metadata. ------------------------------------------------------ */

MODULE_AUTHOR("Maximilian Luz <luzmaximilian@gmail.com>");
MODULE_DESCRIPTION("Interface for Qualcomm TrEE/TZ secure OS and secure applications");
MODULE_LICENSE("GPL");
