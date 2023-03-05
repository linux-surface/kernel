// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Interface driver for the Qualcomm Secure Execution Environment (SEE) /
 * TrustZone OS (TzOS). Manages communication via the QSEECOM interface, using
 * Secure Channel Manager (SCM) calls.
 *
 * Copyright (C) 2023 Maximilian Luz <luzmaximilian@gmail.com>
 */

#include <asm/barrier.h>
#include <linux/device.h>
#include <linux/firmware/qcom/qcom_scm.h>
#include <linux/kernel.h>
#include <linux/mfd/core.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/string.h>

#include <linux/firmware/qcom/qcom_qseecom.h>


/* -- Secure-OS SCM call interface. ----------------------------------------- */

static int __qseecom_scm_call(const struct qcom_scm_desc *desc,
			      struct qseecom_scm_resp *res)
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
 * qseecom_scm_call() - Perform a QSEECOM SCM call.
 * @qsee: The QSEECOM device.
 * @desc: SCM call descriptor.
 * @res:  SCM call response (output).
 *
 * Performs the QSEECOM SCM call described by @desc, returning the response in
 * @rsp.
 *
 * Return: Returns zero on success, nonzero on failure.
 */
int qseecom_scm_call(struct qseecom_device *qsee, const struct qcom_scm_desc *desc,
		     struct qseecom_scm_resp *res)
{
	int status;

	/*
	 * Note: Multiple QSEECOM SCM calls should not be executed same time,
	 * so lock things here. This needs to be extended to callback/listener
	 * handling when support for that is implemented.
	 */

	mutex_lock(&qsee->scm_call_lock);
	status = __qseecom_scm_call(desc, res);
	mutex_unlock(&qsee->scm_call_lock);

	dev_dbg(qsee->dev, "%s: owner=%x, svc=%x, cmd=%x, status=%lld, type=%llx, data=%llx",
		__func__, desc->owner, desc->svc, desc->cmd, res->status,
		res->resp_type, res->data);

	if (status) {
		dev_err(qsee->dev, "qcom_scm_call failed with error %d\n", status);
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
	WARN_ON(res->status == QSEECOM_RESULT_INCOMPLETE);
	WARN_ON(res->status == QSEECOM_RESULT_BLOCKED_ON_LISTENER);

	return 0;
}
EXPORT_SYMBOL_GPL(qseecom_scm_call);


/* -- Secure App interface. ------------------------------------------------- */

/**
 * qseecom_app_get_id() - Query the app ID for a given SEE app name.
 * @qsee:     The QSEECOM device.
 * @app_name: The name of the app.
 * @app_id:   The returned app ID.
 *
 * Query and return the application ID of the SEE app identified by the given
 * name. This returned ID is the unique identifier of the app required for
 * subsequent communication.
 *
 * Return: Returns zero on success, nonzero on failure. Returns -ENOENT if the
 * app has not been loaded or could not be found.
 */
int qseecom_app_get_id(struct qseecom_device *qsee, const char *app_name, u32 *app_id)
{
	unsigned long name_buf_size = QSEECOM_MAX_APP_NAME_SIZE;
	unsigned long app_name_len = strlen(app_name);
	struct qcom_scm_desc desc = {};
	struct qseecom_scm_resp res = {};
	dma_addr_t name_buf_phys;
	char *name_buf;
	int status;

	if (app_name_len >= name_buf_size)
		return -EINVAL;

	name_buf = kzalloc(name_buf_size, GFP_KERNEL);
	if (!name_buf)
		return -ENOMEM;

	memcpy(name_buf, app_name, app_name_len);

	name_buf_phys = dma_map_single(qsee->dev, name_buf, name_buf_size, DMA_TO_DEVICE);
	if (dma_mapping_error(qsee->dev, name_buf_phys)) {
		kfree(name_buf);
		dev_err(qsee->dev, "failed to map dma address\n");
		return -EFAULT;
	}

	desc.owner = QSEECOM_TZ_OWNER_QSEE_OS;
	desc.svc = QSEECOM_TZ_SVC_APP_MGR;
	desc.cmd = 0x03;
	desc.arginfo = QCOM_SCM_ARGS(2, QCOM_SCM_RW, QCOM_SCM_VAL);
	desc.args[0] = name_buf_phys;
	desc.args[1] = app_name_len;

	status = qseecom_scm_call(qsee, &desc, &res);
	dma_unmap_single(qsee->dev, name_buf_phys, name_buf_size, DMA_TO_DEVICE);
	kfree(name_buf);

	if (status)
		return status;

	if (res.status != QSEECOM_RESULT_SUCCESS)
		return -ENOENT;

	*app_id = res.data;
	return 0;
}
EXPORT_SYMBOL_GPL(qseecom_app_get_id);

/**
 * qseecom_app_send() - Send to and receive data from a given SEE app.
 * @qsee:   The QSEECOM device.
 * @app_id: The ID of the app to communicate with.
 * @req:    DMA region of the request sent to the app.
 * @rsp:    DMA region of the response returned by the app.
 *
 * Sends a request to the SEE app identified by the given ID and read back its
 * response. The caller must provide two DMA memory regions, one for the
 * request and one for the response, and fill out the @req region with the
 * respective (app-specific) request data. The SEE app reads this and returns
 * its response in the @rsp region.
 *
 * Return: Returns zero on success, nonzero on failure.
 */
int qseecom_app_send(struct qseecom_device *qsee, u32 app_id, struct qseecom_dma *req,
		     struct qseecom_dma *rsp)
{
	struct qseecom_scm_resp res = {};
	int status;

	struct qcom_scm_desc desc = {
		.owner = QSEECOM_TZ_OWNER_TZ_APPS,
		.svc = QSEECOM_TZ_SVC_APP_ID_PLACEHOLDER,
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

	status = qseecom_scm_call(qsee, &desc, &res);

	/* Make sure we don't attempt any reads before the SCM call is done. */
	dma_rmb();

	if (status)
		return status;

	if (res.status != QSEECOM_RESULT_SUCCESS)
		return -EIO;

	return 0;
}
EXPORT_SYMBOL_GPL(qseecom_app_send);


/* -- Platform specific data. ----------------------------------------------- */

struct qseecom_data {
	const struct mfd_cell *cells;
	int num_cells;
};

static const struct mfd_cell qseecom_cells_sc8280xp[] = {
	{ .name = "qcom_qseecom_uefisecapp", },
};

static const struct qseecom_data qseecom_data_sc8280xp = {
	.cells = qseecom_cells_sc8280xp,
	.num_cells = ARRAY_SIZE(qseecom_cells_sc8280xp),
};

static const struct of_device_id qseecom_dt_match[] = {
	{ .compatible = "qcom,qseecom-sc8280xp", .data = &qseecom_data_sc8280xp },
	{ .compatible = "qcom,qseecom", },
	{ }
};
MODULE_DEVICE_TABLE(of, qseecom_dt_match);


/* -- Driver setup. --------------------------------------------------------- */

static int qseecom_setup_scm_link(struct platform_device *pdev)
{
	const u32 flags = DL_FLAG_PM_RUNTIME | DL_FLAG_AUTOREMOVE_CONSUMER;
	struct platform_device *scm_dev;
	struct device_node *scm_node;
	struct device_link *link;
	int status = 0;

	if (!pdev->dev.of_node)
		return -ENODEV;

	/* Find the SCM device. */
	scm_node = of_parse_phandle(pdev->dev.of_node, "qcom,scm", 0);
	if (!scm_node)
		return -ENOENT;

	scm_dev = of_find_device_by_node(scm_node);
	if (!scm_dev) {
		status = -ENODEV;
		goto put;
	}

	/* Establish the device link. */
	link = device_link_add(&pdev->dev, &scm_dev->dev, flags);
	if (!link) {
		status = -EINVAL;
		goto put;
	}

	/* Make sure SCM has a driver bound, otherwise defer probe. */
	if (link->supplier->links.status != DL_DEV_DRIVER_BOUND) {
		status = -EPROBE_DEFER;
		goto put;
	}

put:
	of_node_put(scm_node);
	return status;
}

static int qseecom_probe(struct platform_device *pdev)
{
	const struct qseecom_data *data;
	struct qseecom_device *qsee;
	int status;

	/* Get platform data. */
	data = of_device_get_match_data(&pdev->dev);

	/* Set up device link. */
	status = qseecom_setup_scm_link(pdev);
	if (status)
		return status;

	/* Set up QSEECOM device. */
	qsee = devm_kzalloc(&pdev->dev, sizeof(*qsee), GFP_KERNEL);
	if (!qsee)
		return -ENOMEM;

	qsee->dev = &pdev->dev;
	mutex_init(&qsee->scm_call_lock);

	platform_set_drvdata(pdev, qsee);

	/* Add child devices. */
	if (data) {
		status = devm_mfd_add_devices(&pdev->dev, PLATFORM_DEVID_NONE, data->cells,
					      data->num_cells, NULL, 0, NULL);
	}

	return status;
}

static struct platform_driver qseecom_driver = {
	.probe = qseecom_probe,
	.driver = {
		.name = "qcom_qseecom",
		.of_match_table = qseecom_dt_match,
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};
module_platform_driver(qseecom_driver);

MODULE_AUTHOR("Maximilian Luz <luzmaximilian@gmail.com>");
MODULE_DESCRIPTION("Driver for Qualcomm QSEECOM secure OS and secure application interface");
MODULE_LICENSE("GPL");
