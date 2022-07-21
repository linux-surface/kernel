// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Interface driver for the Qualcomm Trusted Execution Environment / TrustZone
 * secure OS. Manages communication via Secure Channel Manager (SCM) calls.
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

int qctee_os_scm_call(struct device *dev, const struct qcom_scm_desc *desc,
		      struct qctee_os_scm_resp *res)
{
	int status;

	status = __qctee_os_scm_call(desc, res);

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
	 *
	 * Note that supporting incomplete/reentrant calls will also require
	 * proper locking here.
	 */
	WARN_ON(res->status == QCTEE_OS_RESULT_INCOMPLETE);
	WARN_ON(res->status == QCTEE_OS_RESULT_BLOCKED_ON_LISTENER);

	return 0;
}
EXPORT_SYMBOL_GPL(qctee_os_scm_call);


/* -- Secure App interface. ------------------------------------------------- */

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
		return -EINVAL;

	*app_id = res.data;
	return 0;
}
EXPORT_SYMBOL_GPL(qctee_app_get_id);

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

	/* Make sure we don't attempt any reads before the SMC call is done. */
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
MODULE_DESCRIPTION("Interface for Qualcomm TEE/TZ secure OS and secure applications");
MODULE_LICENSE("GPL");
