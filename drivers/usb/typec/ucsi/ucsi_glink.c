// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2019-2020, The Linux Foundation. All rights reserved.
// Copyright (c) 2021, Linaro Ltd

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/power_supply.h>
#include <linux/regmap.h>
#include <linux/slab.h>
#include <linux/regulator/driver.h>
#include <linux/rpmsg.h>
#include <linux/soc/qcom/pdr.h>

#include "ucsi.h"

#define MSG_OWNER_BC		32778
#define MSG_TYPE_NOTIFY		2
#define MSG_TYPE_REQ_RESP	1

#define BC_SET_NOTIFY_REQ	0x4
#define BC_NOTIFY_IND		0x7
#define BC_BATTERY_STATUS_GET	0x30
#define BC_BATTERY_STATUS_SET	0x31
#define BC_USB_STATUS_GET	0x32
#define BC_USB_STATUS_SET	0x33
#define BC_WLS_STATUS_GET	0x34
#define BC_WLS_STATUS_SET	0x35

#define MODEL_NAME_LEN		128

/* PPM specific definitions */
#define MSG_OWNER_UC                    32779
#define MSG_TYPE_REQ_RESP               1
#define UCSI_BUF_SIZE                   48

#define UC_NOTIFY_RECEIVER_UCSI         0x0
#define UC_UCSI_READ_BUF_REQ            0x11
#define UC_UCSI_WRITE_BUF_REQ           0x12
#define UC_UCSI_USBC_NOTIFY_IND         0x13

/**
 * struct pmic_glink_hdr - PMIC Glink message header
 * @owner:      message owner for a client
 * @type:       message type
 * @opcode:     message opcode
 */
struct pmic_glink_hdr {
	u32 owner;
	u32 type;
	u32 opcode;
};

struct ucsi_read_buf_req_msg {
	struct pmic_glink_hdr   hdr;
};

struct ucsi_read_buf_resp_msg {
	struct pmic_glink_hdr   hdr;
	u8                      buf[UCSI_BUF_SIZE];
	u32                     ret_code;
};

struct ucsi_write_buf_req_msg {
	struct pmic_glink_hdr   hdr;
	u8                      buf[UCSI_BUF_SIZE];
	u32                     reserved;
};

struct ucsi_write_buf_resp_msg {
	struct pmic_glink_hdr   hdr;
	u32                     ret_code;
};

struct ucsi_notify_ind_msg {
	struct pmic_glink_hdr   hdr;
	u32                     notification;
	u32                     receiver;
	u32                     reserved;
};

struct ucsi_glink {
	struct device *dev;
	struct rpmsg_endpoint *ept;

	struct ucsi *ucsi;
	struct completion ack;
	struct completion sync_ack;
	struct mutex lock;

	u8 read_buf[UCSI_BUF_SIZE];

	int sync_val;
	bool sync_pending;

	struct pdr_handle *pdr;
};

static int ucsi_glink_read(struct ucsi *ucsi, unsigned int offset,
			   void *val, size_t val_len)
{
	struct ucsi_glink *ug = ucsi_get_drvdata(ucsi);
	struct ucsi_read_buf_req_msg req = {};
	unsigned long left;
	int ret;

	req.hdr.owner = MSG_OWNER_UC;
	req.hdr.type = MSG_TYPE_REQ_RESP;
	req.hdr.opcode = UC_UCSI_READ_BUF_REQ;

	printk(KERN_ERR "%s(%u, %zd)\n", __func__, offset, val_len);

	mutex_lock(&ug->lock);
	reinit_completion(&ug->ack);

	print_hex_dump(KERN_ERR, ">UCSI", DUMP_PREFIX_OFFSET, 16, 1, &req, sizeof(req), true);

	ret = rpmsg_send(ug->ept, &req, sizeof(req));
	if (ret < 0) {
		dev_err(ug->dev, "failed to send UCSI read request: %d\n", ret);
		goto out_unlock;
	}

	left = wait_for_completion_timeout(&ug->ack, 5 * HZ);
	if (!left) {
		dev_err(ug->dev, "timeout waiting for UCSI read response\n");
		ret = -ETIMEDOUT;
		goto out_unlock;
	}

	memcpy(val, &ug->read_buf[offset], val_len);
	ret = 0;

out_unlock:
	mutex_unlock(&ug->lock);

	printk(KERN_ERR "%s(%u, %zd) = %d\n", __func__, offset, val_len, ret);

	return ret;
}

static int ucsi_glink_locked_write(struct ucsi_glink *ug, unsigned int offset,
				   const void *val, size_t val_len)
{
	struct ucsi_write_buf_req_msg req = {};
	unsigned long left;
	int ret;

	req.hdr.owner = MSG_OWNER_UC;
	req.hdr.type = MSG_TYPE_REQ_RESP;
	req.hdr.opcode = UC_UCSI_WRITE_BUF_REQ;
	memcpy(&req.buf[offset], val, val_len);

	reinit_completion(&ug->ack);

	print_hex_dump(KERN_ERR, ">UCSI", DUMP_PREFIX_OFFSET, 16, 1, &req, sizeof(req), true);

	ret = rpmsg_send(ug->ept, &req, sizeof(req));
	if (ret < 0) {
		dev_err(ug->dev, "failed to send UCSI write request: %d\n", ret);
		return ret;
	}

	left = wait_for_completion_timeout(&ug->ack, 5 * HZ);
	if (!left) {
		dev_err(ug->dev, "timeout waiting for UCSI write response\n");
		return -ETIMEDOUT;
	}

	return 0;
}

static int ucsi_glink_async_write(struct ucsi *ucsi, unsigned int offset,
				  const void *val, size_t val_len)
{
	struct ucsi_glink *ug = ucsi_get_drvdata(ucsi);
	int ret;

	printk(KERN_ERR "%s(%u, %zd)\n", __func__, offset, val_len);

	mutex_lock(&ug->lock);
	ret = ucsi_glink_locked_write(ug, offset, val, val_len);
	mutex_unlock(&ug->lock);

	printk(KERN_ERR "%s(%u, %zd) = %d\n", __func__, offset, val_len, ret);

	return ret;
}

static int ucsi_glink_sync_write(struct ucsi *ucsi, unsigned int offset,
				 const void *val, size_t val_len)
{
	struct ucsi_glink *ug = ucsi_get_drvdata(ucsi);
	unsigned long left;
	int ret;

	printk(KERN_ERR "%s(%u, %zd)\n", __func__, offset, val_len);

	mutex_lock(&ug->lock);
	reinit_completion(&ug->sync_ack);
	ug->sync_pending = true;

	ret = ucsi_glink_locked_write(ug, offset, val, val_len);

	left = wait_for_completion_timeout(&ug->sync_ack, 5 * HZ);
	if (!left) {
		dev_err(ug->dev, "timeout waiting for UCSI sync write response\n");
		ret = -ETIMEDOUT;
		goto out_unlock;
	}

	if (ug->sync_val)
		dev_err(ug->dev, "sync write returned: %d\n", ug->sync_val);

out_unlock:
	ug->sync_pending = false;
	mutex_unlock(&ug->lock);

	printk(KERN_ERR "%s(%u, %zd) = %d\n", __func__, offset, val_len, ret);

	return 0;
}

static const struct ucsi_operations ucsi_glink_ops = {
	.read = ucsi_glink_read,
	.sync_write = ucsi_glink_sync_write,
	.async_write = ucsi_glink_async_write
};

static void ucsi_glink_read_ack(struct ucsi_glink *ug, void *data, int len)
{
	struct ucsi_read_buf_resp_msg *resp = data;

	memcpy(ug->read_buf, resp->buf, UCSI_BUF_SIZE);
	complete(&ug->ack);
}

static void ucsi_glink_write_ack(struct ucsi_glink *ug, void *data, int len)
{
	struct ucsi_write_buf_resp_msg *resp = data;

	ug->sync_val = resp->ret_code;
	complete(&ug->ack);
}

static void ucsi_glink_notify(struct ucsi_glink *ug, void *data, int len)
{
	struct ucsi_notify_ind_msg *msg = data;
	unsigned int con_num;
	u32 cci;

	cci = be32_to_cpu(msg->notification);

	printk(KERN_ERR "%s() cci: %#x\n", __func__, cci);

	if (cci & (UCSI_CCI_ACK_COMPLETE | UCSI_CCI_COMMAND_COMPLETE))
		complete(&ug->sync_ack);

	con_num = UCSI_CCI_CONNECTOR(cci);

	if (con_num)
		ucsi_connector_change(ug->ucsi, con_num);
}

static int ucsi_glink_callback(struct rpmsg_device *rpdev, void *data,
			       int len, void *priv, u32 addr)
{
	struct ucsi_glink *ug = dev_get_drvdata(&rpdev->dev);
	struct pmic_glink_hdr *hdr = data;

	printk(KERN_ERR "owner: %u type: %u opcode: %#x len:%u\n", hdr->owner, hdr->type, hdr->opcode, len);
	print_hex_dump(KERN_ERR, "UCSI>", DUMP_PREFIX_OFFSET, 16, 1, data, len, true);

	switch (hdr->opcode) {
	case UC_UCSI_READ_BUF_REQ:
		ucsi_glink_read_ack(ug, data, len);
		break;
	case UC_UCSI_WRITE_BUF_REQ:
		ucsi_glink_write_ack(ug, data, len);
		break;
	case UC_UCSI_USBC_NOTIFY_IND:
		ucsi_glink_notify(ug, data, len);
		break;
	}

	return 0;
}

static void ucsi_glink_pdr_callback(int state, char *svc_path, void *priv)
{
	struct ucsi_glink *ug = priv;

	printk(KERN_ERR "%s(%d)\n", __func__, state);

	switch (state) {
	case SERVREG_SERVICE_STATE_UP:
		ucsi_register(ug->ucsi);
		break;
	case SERVREG_SERVICE_STATE_DOWN:
		ucsi_unregister(ug->ucsi);
		break;
	}
}

static int ucsi_glink_probe(struct rpmsg_device *rpdev)
{
	struct ucsi_glink *ug;

	ug = devm_kzalloc(&rpdev->dev, sizeof(*ug), GFP_KERNEL);
	if (!ug)
		return -ENOMEM;

	dev_set_drvdata(&rpdev->dev, ug);

	init_completion(&ug->ack);
	init_completion(&ug->sync_ack);
	mutex_init(&ug->lock);

	ug->dev = &rpdev->dev;
	ug->ept = rpdev->ept;

	ug->ucsi = ucsi_create(&rpdev->dev, &ucsi_glink_ops);
	if (IS_ERR(ug->ucsi))
		return PTR_ERR(ug->ucsi);

	ucsi_set_drvdata(ug->ucsi, ug);

	ug->pdr = pdr_handle_alloc(ucsi_glink_pdr_callback, ug);
	if (IS_ERR(ug->pdr)) {
		dev_err(&rpdev->dev, "failed to initalize pdr\n");
		return PTR_ERR(ug->pdr);
	}

	pdr_add_lookup(ug->pdr, "tms/servreg", "msm/adsp/charger_pd");

	return 0;
}

static const struct of_device_id ucsi_glink_of_match[] = {
	{ .compatible = "qcom,glink-ucsi", },
	{}
};
MODULE_DEVICE_TABLE(of, ucsi_glink_of_match);

static const struct rpmsg_device_id ucsi_glink_id_match[] = {
	{ "PMIC_RTR_ADSP_APPS" },
	{}
};

static struct rpmsg_driver ucsi_glink_driver = {
	.probe = ucsi_glink_probe,
	.callback = ucsi_glink_callback,
	.id_table = ucsi_glink_id_match,
	.drv  = {
		.name  = "qcom_ucsi_glink",
	},
};
module_rpmsg_driver(ucsi_glink_driver);

MODULE_DESCRIPTION("Qualcomm LPASS charger driver");
MODULE_LICENSE("GPL v2");
