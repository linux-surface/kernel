// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2019-2020, The Linux Foundation. All rights reserved.
// Copyright (c) 2021, Linaro Ltd

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
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
#include <linux/usb/typec_altmode.h>
#include <linux/usb/typec_dp.h>
#include <linux/usb/typec_mux.h>

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

#define MSG_OWNER_USBC_PAN      32780
#define MSG_TYPE_REQ_RESP       1
#define USBC_WRITE_BUFFER_SIZE  8

#define USBC_CMD_WRITE_REQ      0x15
#define USBC_NOTIFY_IND         0x16

enum altmode_send_msg_type {
	ALTMODE_PAN_EN = 0x10,
	ALTMODE_PAN_ACK,
};

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

struct usbc_write_req {
	struct pmic_glink_hdr   hdr;
	u32 cmd;
	u32 arg;
	u32                     reserved;
};

struct glink_altmode_port {
	struct typec_switch *typec_switch;
	struct typec_mux *mux;
	struct typec_mux_state state;
	struct typec_altmode dp_alt;
};

struct ucsi_glink {
	struct device *dev;
	struct rpmsg_endpoint *ept;

	struct ucsi *ucsi;
	struct completion read_ack;
	struct completion write_ack;
	struct completion sync_ack;
	bool sync_pending;
	struct mutex lock;

	struct completion pan_ack;

	u8 read_buf[UCSI_BUF_SIZE];

	int sync_val;

	struct pdr_handle *pdr;

	struct work_struct notify_work;

	struct work_struct altmode_work;
	u32 altmode_msg;

	struct glink_altmode_port ports[2];
};

static int glink_altmode_write(struct ucsi_glink *ug, u32 cmd, u32 arg)
{
	struct usbc_write_req req = {};
	int ret;

	req.hdr.owner = MSG_OWNER_UC;
	req.hdr.type = MSG_TYPE_REQ_RESP;
	req.hdr.opcode = USBC_CMD_WRITE_REQ;
	req.cmd = cmd;
	req.arg = arg;

	ret = rpmsg_send(ug->ept, &req, sizeof(req));
	if (ret < 0)
		dev_err(ug->dev, "failed to send altmode request %d\n", ret);

	return ret;
}

static int glink_altmode_enable(struct ucsi_glink *ug)
{
	unsigned long left;
	int ret;

	ret = glink_altmode_write(ug, ALTMODE_PAN_EN, 0);
	if (ret)
		return ret;

	left = wait_for_completion_timeout(&ug->pan_ack, 5 * HZ);
	if (!left) {
		dev_err(ug->dev, "timeout waiting for pan enable ack\n");
		return -ETIMEDOUT;
	}

	return 0;
}

static int glink_altmode_ack(struct ucsi_glink *ug, int port)
{
	unsigned long left;
	int ret;

	ret = glink_altmode_write(ug, ALTMODE_PAN_ACK, port);
	if (ret)
		return ret;

	left = wait_for_completion_timeout(&ug->pan_ack, 5 * HZ);
	if (!left) {
		dev_err(ug->dev, "timeout waiting for pan enable ack\n");
		return -ETIMEDOUT;
	}

	return 0;
}

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

	mutex_lock(&ug->lock);
	memset(ug->read_buf, 0, sizeof(ug->read_buf));
	reinit_completion(&ug->read_ack);

	ret = rpmsg_send(ug->ept, &req, sizeof(req));
	if (ret < 0) {
		dev_err(ug->dev, "failed to send UCSI read request: %d\n", ret);
		goto out_unlock;
	}

	left = wait_for_completion_timeout(&ug->read_ack, 5 * HZ);
	if (!left) {
		dev_err(ug->dev, "timeout waiting for UCSI read response\n");
		ret = -ETIMEDOUT;
		goto out_unlock;
	}

	memcpy(val, &ug->read_buf[offset], val_len);
	ret = 0;

out_unlock:
	mutex_unlock(&ug->lock);

	return ret;
}

static int ucsi_glink_locked_write(struct ucsi_glink *ug, unsigned int offset,
				   const void *val, size_t val_len)
{
	struct ucsi_write_buf_req_msg req = {};
	unsigned long left;
	int ret;

	// msleep(100);

	req.hdr.owner = MSG_OWNER_UC;
	req.hdr.type = MSG_TYPE_REQ_RESP;
	req.hdr.opcode = UC_UCSI_WRITE_BUF_REQ;
	memcpy(&req.buf[offset], val, val_len);

	reinit_completion(&ug->write_ack);

//	print_hex_dump(KERN_ERR, "  UCSI SEND ", DUMP_PREFIX_OFFSET, 16, 1, req.buf, sizeof(req.buf), true);

	ret = rpmsg_send(ug->ept, &req, sizeof(req));
	if (ret < 0) {
		dev_err(ug->dev, "failed to send UCSI write request: %d\n", ret);
		return ret;
	}

	left = wait_for_completion_timeout(&ug->write_ack, 5 * HZ);
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


	mutex_lock(&ug->lock);
	ret = ucsi_glink_locked_write(ug, offset, val, val_len);
	mutex_unlock(&ug->lock);

	return ret;
}

#if 0
static int ucsi_glink_ack_command(struct ucsi_glink *ug)
{
	unsigned long left;
	u64 ctrl;
	int ret;

	ctrl = UCSI_ACK_CC_CI;
	ctrl |= UCSI_ACK_COMMAND_COMPLETE;

	mutex_lock(&ug->lock);
	reinit_completion(&ug->sync_ack);
	ret = ucsi_glink_locked_write(ug, UCSI_CONTROL, &ctrl, sizeof(ctrl));
	mutex_unlock(&ug->lock);

	left = wait_for_completion_timeout(&ug->sync_ack, 5 * HZ);
	if (!left) {
		dev_err(ug->dev, "timeout waiting for UCSI sync write response\n");
		ret = -ETIMEDOUT;
	}

	return ret;
}
#endif

static int ucsi_glink_sync_write(struct ucsi *ucsi, unsigned int offset,
				 const void *val, size_t val_len)
{
	struct ucsi_glink *ug = ucsi_get_drvdata(ucsi);
	unsigned long left;
	u64 command;
	int ret;

	if (offset == UCSI_CONTROL) {
		command = *(u64*)val;
		if (UCSI_COMMAND(command) == UCSI_GET_ALTERNATE_MODES) {
			command &= ~(7 << 16);
			command |= UCSI_GET_ALTMODE_RECIPIENT(UCSI_RECIPIENT_CON);
			printk(KERN_ERR "forcing recipient to CON\n");
		}

		*(u64*)val = command;
	}

	mutex_lock(&ug->lock);
	ug->sync_val = 0;
	reinit_completion(&ug->sync_ack);
	ug->sync_pending = true;
	ret = ucsi_glink_locked_write(ug, offset, val, val_len);
	mutex_unlock(&ug->lock);

	left = wait_for_completion_timeout(&ug->sync_ack, 5 * HZ);
	if (!left) {
		dev_err(ug->dev, "timeout waiting for UCSI sync write response\n");
		ret = -ETIMEDOUT;
	} else if (ug->sync_val) {
		dev_err(ug->dev, "sync write returned: %d\n", ug->sync_val);
	}

	ug->sync_pending = false;

	return ret;
}

static const struct ucsi_operations ucsi_glink_ops = {
	.read = ucsi_glink_read,
	.sync_write = ucsi_glink_sync_write,
	.async_write = ucsi_glink_async_write
};

static void ucsi_glink_read_ack(struct ucsi_glink *ug, void *data, int len)
{
	struct ucsi_read_buf_resp_msg *resp = data;

	if (resp->ret_code)
		return;

	memcpy(ug->read_buf, resp->buf, UCSI_BUF_SIZE);
	complete(&ug->read_ack);
}

static void ucsi_glink_write_ack(struct ucsi_glink *ug, void *data, int len)
{
	struct ucsi_write_buf_resp_msg *resp = data;

	if (resp->ret_code)
		return;

	ug->sync_val = resp->ret_code;
	complete(&ug->write_ack);
}

static void ucsi_glink_notify(struct work_struct *work)
{
	struct ucsi_glink *ug = container_of(work, struct ucsi_glink, notify_work);
	unsigned int con_num;
	u32 cci;
	int ret;

	ret = ucsi_glink_read(ug->ucsi, UCSI_CCI, &cci, sizeof(cci));
	if (ret) {
		dev_err(ug->dev, "failed to read cci on notification\n");
		return;
	}

	// trace_printk("cci: %#x\n", cci);

	con_num = UCSI_CCI_CONNECTOR(cci);
	if (con_num) {
		ucsi_connector_change(ug->ucsi, con_num);
	}

	if (ug->sync_pending && cci & UCSI_CCI_BUSY) {
		ug->sync_val = -EBUSY;
		complete(&ug->sync_ack);
	} else if (ug->sync_pending && cci & (UCSI_CCI_ACK_COMPLETE | UCSI_CCI_COMMAND_COMPLETE)) {
		complete(&ug->sync_ack);
	}
}

static int ucsi_altmode_enable_dp(struct ucsi_glink *ug, struct glink_altmode_port *port, u8 flags)
{
	struct typec_displayport_data dp_data = {};
	int ret;

//	if (flags != 67)
//		return 0;

	dp_data.status = DP_STATUS_ENABLED;
	if (flags & 0x40)
		dp_data.status |= DP_STATUS_HPD_STATE;
	if (flags & 0x80)
		dp_data.status |= DP_STATUS_IRQ_HPD;
	dp_data.conf = DP_CONF_SET_PIN_ASSIGN(flags & 0x3f);

	port->state.alt = &port->dp_alt;
	port->state.data = &dp_data;
	port->state.mode = TYPEC_MODAL_STATE(TYPEC_STATE_MODAL);

	ret = typec_mux_set(port->mux, &port->state);
	if (ret)
		dev_err(ug->dev, "failed to switch mux to DP\n");
	return ret;
}

static int ucsi_altmode_enable_usb(struct ucsi_glink *ug, struct glink_altmode_port *port, u8 flags)
{
	int ret;

	port->state.alt = NULL;
	port->state.data = NULL;
	port->state.mode = TYPEC_STATE_USB;

	ret = typec_mux_set(port->mux, &port->state);
	if (ret)
		dev_err(ug->dev, "failed to switch mux to USB\n");
	return ret;
}

static void ucsi_altmode_notify(struct work_struct *work)
{
	struct ucsi_glink *ug = container_of(work, struct ucsi_glink, altmode_work);
	struct glink_altmode_port *alt_port;
	u8 orientation;
	u8 port;
	u8 mux;
	u8 flags;

	port = ug->altmode_msg & 0xff;
	orientation = (ug->altmode_msg >> 8) & 0xff;
	mux = (ug->altmode_msg >> 16) & 0xff;
	flags = (ug->altmode_msg >> 24) & 0xff;

	// trace_printk("port: %d orientation: %d mux: %d flags: %d\n", port, orientation, mux, flags);

	if (port >= ARRAY_SIZE(ug->ports)) {
		dev_err(ug->dev, "altmode notification on unexpected port %d\n", port);
		glink_altmode_ack(ug, port);
		return;
	}

	alt_port = &ug->ports[port];

	typec_switch_set(alt_port->typec_switch, orientation ? TYPEC_ORIENTATION_REVERSE : TYPEC_ORIENTATION_NORMAL);

	switch (mux) {
	case 2:
		ucsi_altmode_enable_dp(ug, alt_port, flags);
		break;
	default:
		ucsi_altmode_enable_usb(ug, alt_port, flags);
		break;
	};

	glink_altmode_ack(ug, port);
}

static void ucsi_usbc_notify(struct ucsi_glink *ug, void *data, int len)
{
	struct ucsi_notify_ind_msg *msg = data;

	//print_hex_dump(KERN_ERR, "NOTIFY ", DUMP_PREFIX_OFFSET, 16, 1, data, len, true);

	switch (msg->receiver) {
	case 0:
		schedule_work(&ug->notify_work);
		break;
	case 1:
		ug->altmode_msg = msg->notification;
		schedule_work(&ug->altmode_work);
		break;
	}
}

static int ucsi_glink_callback(struct rpmsg_device *rpdev, void *data,
			       int len, void *priv, u32 addr)
{
	struct ucsi_glink *ug = dev_get_drvdata(&rpdev->dev);
	struct pmic_glink_hdr *hdr = data;

	// trace_printk("owner: %u type: %u opcode: %#x len:%u\n", hdr->owner, hdr->type, hdr->opcode, len);

	switch (hdr->opcode) {
	case UC_UCSI_READ_BUF_REQ:
		ucsi_glink_read_ack(ug, data, len);
		break;
	case UC_UCSI_WRITE_BUF_REQ:
		ucsi_glink_write_ack(ug, data, len);
		break;
	case UC_UCSI_USBC_NOTIFY_IND:
		ucsi_usbc_notify(ug, data, len);
		break;
	case 0x15:
		complete(&ug->pan_ack);
//		schedule_work(&ug->notify_work);
		break;
	}

	return 0;
}

static void ucsi_glink_pdr_callback(int state, char *svc_path, void *priv)
{
	struct ucsi_glink *ug = priv;

	// printk(KERN_ERR "  %s(%d)\n", __func__, state);

	switch (state) {
	case SERVREG_SERVICE_STATE_UP:
		glink_altmode_enable(ug);
//		ucsi_register(ug->ucsi);
		break;
	case SERVREG_SERVICE_STATE_DOWN:
//		ucsi_unregister(ug->ucsi);
		break;
	}
}

static int ucsi_glink_probe(struct rpmsg_device *rpdev)
{
	struct glink_altmode_port *alt_port;
	struct typec_altmode_desc mux_desc = {};
	struct fwnode_handle *fwnode;
	struct device *dev = &rpdev->dev;
	struct ucsi_glink *ug;
	int port = 0;

	ug = devm_kzalloc(&rpdev->dev, sizeof(*ug), GFP_KERNEL);
	if (!ug)
		return -ENOMEM;

	dev_set_drvdata(&rpdev->dev, ug);

	INIT_WORK(&ug->notify_work, ucsi_glink_notify);
	INIT_WORK(&ug->altmode_work, ucsi_altmode_notify);
	init_completion(&ug->read_ack);
	init_completion(&ug->write_ack);
	init_completion(&ug->sync_ack);
	init_completion(&ug->pan_ack);
	mutex_init(&ug->lock);

	ug->dev = &rpdev->dev;
	ug->ept = rpdev->ept;

	ug->ucsi = ucsi_create(&rpdev->dev, &ucsi_glink_ops);
	if (IS_ERR(ug->ucsi))
		return PTR_ERR(ug->ucsi);

	ucsi_set_drvdata(ug->ucsi, ug);

	device_for_each_child_node(dev, fwnode) {
		if (port >= ARRAY_SIZE(ug->ports)) {
			dev_err(dev, "too many connectors\n");
			return -EINVAL;
		}

		alt_port = &ug->ports[port];

		alt_port->dp_alt.svid = USB_TYPEC_DP_SID;
		alt_port->dp_alt.mode = USB_TYPEC_DP_MODE;
		alt_port->dp_alt.active = 1;
		
		alt_port->state.alt = NULL;
		alt_port->state.mode = TYPEC_STATE_USB;
		alt_port->state.data = NULL;

		mux_desc.svid = USB_TYPEC_DP_SID;
		mux_desc.mode = USB_TYPEC_DP_MODE;
		alt_port->mux = fwnode_typec_mux_get(fwnode, &mux_desc);
		if (IS_ERR(alt_port->mux)) {
			dev_err(dev, "%d: failed to find mode-switch\n", port);
		} else if (!alt_port->mux) {
			dev_err(dev, "%d: mux is NULL\n", port);
		} else {
			dev_err(dev, "%d: mux found\n", port);
		}

		alt_port->typec_switch = fwnode_typec_switch_get(fwnode);
		if (IS_ERR(alt_port->typec_switch)) {
			dev_err(dev, "%d: failed to find orientation-switch\n", port);
		} else if (!alt_port->typec_switch) {
			dev_err(dev, "%d: typec_switch is NULL\n", port);
		} else {
			dev_err(dev, "%d: typec_switch found\n", port);
		}
		port++;
	}

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
//MODULE_DEVICE_TABLE(of, ucsi_glink_of_match);

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
