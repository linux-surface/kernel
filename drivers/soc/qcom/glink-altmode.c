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

#define MSG_OWNER_USBC_PAN      32780
#define MSG_TYPE_REQ_RESP       1
#define USBC_WRITE_BUFFER_SIZE  8

#define USBC_CMD_WRITE_REQ      0x15
#define USBC_NOTIFY_IND         0x16

enum altmode_send_msg_type {
	ALTMODE_PAN_EN = 0x10,
	ALTMODE_PAN_ACK,
};

struct usbc_write_req {
	struct pmic_glink_hdr   hdr;
	u8                      buf[USBC_WRITE_BUFFER_SIZE];
	u32                     reserved;
};

struct glink_altmode {
	struct device *dev;
	struct rpmsg_endpoint *ept;

	struct mutex lock;

	struct pdr_handle *pdr;
};

static int glink_altmode_write(struct glink_altmode *gam, const void *val, size_t val_len)
{
	struct usbc_write_req req = {};
	int ret;

	req.hdr.owner = MSG_OWNER_USBC_PAN;
	req.hdr.type = MSG_TYPE_REQ_RESP;
	req.hdr.opcode = USBC_CMD_WRITE_REQ;

	memcpy(req.buf, val, val_len);

	ret = rpmsg_send(gam->ept, &req, sizeof(req));
	if (ret < 0)
		dev_err(gam->dev, "failed to send altmode request %d\n", ret);

	return ret;
}

static int glink_altmode_enable(struct glink_altmode *gam)
{
	u32 msg = ALTMODE_PAN_EN;

	return glink_altmode_write(gam, &msg, sizeof(msg));
}

static int glink_altmode_callback(struct rpmsg_device *rpdev, void *data,
		int len, void *priv, u32 addr)
{
	//struct glink_altmode *gam = dev_get_drvdata(&rpdev->dev);
	struct pmic_glink_hdr *hdr = data;

	printk(KERN_ERR "owner: %u type: %u opcode: %#x len:%u\n", hdr->owner, hdr->type, hdr->opcode, len);
	print_hex_dump(KERN_ERR, "UCSI>", DUMP_PREFIX_OFFSET, 16, 1, data, len, true);

#if 0
	switch (hdr->opcode) {
	case UC_UCSI_READ_BUF_REQ:
		glink_altmode_read_ack(gam, data, len);
		break;
	case UC_UCSI_WRITE_BUF_REQ:
		glink_altmode_write_ack(gam, data, len);
		break;
	case UC_UCSI_USBC_NOTIFY_IND:
		glink_altmode_notify(gam, data, len);
		break;
	}
#endif

	return 0;
}


static void glink_altmode_pdr_callback(int state, char *svc_path, void *priv)
{
	struct glink_altmode *gam = priv;

	printk(KERN_ERR "%s(%d)\n", __func__, state);

	switch (state) {
	case SERVREG_SERVICE_STATE_UP:
		glink_altmode_enable(gam);
		break;
	case SERVREG_SERVICE_STATE_DOWN:
		break;
	}
}

static int glink_altmode_probe(struct rpmsg_device *rpdev)
{
	struct glink_altmode *gam;

	gam = devm_kzalloc(&rpdev->dev, sizeof(*gam), GFP_KERNEL);
	if (!gam)
		return -ENOMEM;

	dev_set_drvdata(&rpdev->dev, gam);

	mutex_init(&gam->lock);

	gam->dev = &rpdev->dev;
	gam->ept = rpdev->ept;

	gam->pdr = pdr_handle_alloc(glink_altmode_pdr_callback, gam);
	if (IS_ERR(gam->pdr)) {
		dev_err(&rpdev->dev, "failed to initalize pdr\n");
		return PTR_ERR(gam->pdr);
	}

	pdr_add_lookup(gam->pdr, "tms/servreg", "msm/adsp/charger_pd");

	return 0;
}

static const struct of_device_id glink_altmode_of_match[] = {
	{ .compatible = "qcom,glink-altmode", },
	{}
};
MODULE_DEVICE_TABLE(of, glink_altmode_of_match);

static const struct rpmsg_device_id glink_altmode_id_match[] = {
	{ "PMIC_RTR_ADSP_APPS" },
	{}
};

static struct rpmsg_driver glink_altmode_driver = {
	.probe = glink_altmode_probe,
	.callback = glink_altmode_callback,
	.id_table = glink_altmode_id_match,
	.drv  = {
		.name  = "qcom_glink_altmode",
	},
};
module_rpmsg_driver(glink_altmode_driver);

MODULE_DESCRIPTION("Qualcomm GLINK altmode driver");
MODULE_LICENSE("GPL v2");
