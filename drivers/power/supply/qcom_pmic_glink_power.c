// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2019-2020, The Linux Foundation. All rights reserved.
 * Copyright (c) 2020-2021, Linaro Ltd
 */

#include <linux/auxiliary_bus.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/power_supply.h>
#include <linux/soc/qcom/pmic_glink.h>

#define BC_SET_NOTIFY_REQ	0x4
#define BC_NOTIFY_IND		0x7
#define BC_BATTERY_STATUS_GET	0x30
#define BC_BATTERY_STATUS_SET	0x31
#define BC_USB_STATUS_GET	0x32
#define BC_USB_STATUS_SET	0x33
#define BC_WLS_STATUS_GET	0x34
#define BC_WLS_STATUS_SET	0x35

#define MODEL_NAME_LEN		128

#define BATT_STATUS		0
#define BATT_HEALTH		1
#define BATT_PRESENT		2
#define BATT_CHG_TYPE		3
#define BATT_CAPACITY		4
#define BATT_SOH		5
#define BATT_VOLT_OCV		6
#define BATT_VOLT_NOW		7
#define BATT_VOLT_MAX		8
#define BATT_CURR_NOW		9
#define BATT_CHG_CTRL_LIM	10
#define BATT_CHG_CTRL_LIM_MAX	11
#define BATT_TEMP		12
#define BATT_TECHNOLOGY		13
#define BATT_CHG_COUNTER	14
#define BATT_CYCLE_COUNT	15
#define BATT_CHG_FULL_DESIGN	16
#define BATT_CHG_FULL		17
#define BATT_MODEL_NAME		18
#define BATT_TTF_AVG		19
#define BATT_TTE_AVG		20
#define BATT_RESISTANCE		21
#define BATT_POWER_NOW		22
#define BATT_POWER_AVG		23

#define USB_ONLINE		0
#define USB_VOLT_NOW		1
#define USB_VOLT_MAX		2
#define USB_CURR_NOW		3
#define USB_CURR_MAX		4
#define USB_INPUT_CURR_LIMIT	5
#define USB_TYPE		6
#define USB_ADAP_TYPE		7
#define USB_MOISTURE_DET_EN	8
#define USB_MOISTURE_DET_STS	9

#define WLS_ONLINE		0
#define WLS_VOLT_NOW		1
#define WLS_VOLT_MAX		2
#define WLS_CURR_NOW		3
#define WLS_CURR_MAX		4
#define WLS_TYPE		5
#define WLS_BOOST_EN		6

struct pmic_glink_bat_enable_notifications {
	struct pmic_glink_hdr hdr;
	__le32 battery_id;
	__le32 power_state;
	__le32 low_capacity;
	__le32 high_capacity;
};

struct pmic_glink_bat_req {
	struct pmic_glink_hdr hdr;
	__le32 battery;
	__le32 property;
	__le32 value;
};

struct pmic_glink_bat_resp {
	struct pmic_glink_hdr hdr;
	__le32 property;
	union {
		struct {
			__le32 value;
			__le32 result;
		} intval;
		struct {
			char model[MODEL_NAME_LEN];
		} strval;
	};
};

struct pmic_glink_bat_notification {
	struct pmic_glink_hdr hdr;
	__le32 notification;
};

struct pmic_glink_power {
	struct device *dev;
	struct pmic_glink_client *client;

	struct power_supply *bat_psy;
	struct power_supply *usb_psy;
	struct power_supply *wls_psy;

	char bat_model[MODEL_NAME_LEN];
	u32 value;
	int error;
	struct completion ack;

	/*
	 * @lock is used to prevent concurrent power supply requests to the
	 * firmware, as it then stops responding.
	 */
	struct mutex lock;
};

static int pmic_glink_ps_send(struct pmic_glink_power *pgp, void *data, size_t len)
{
	unsigned long left;
	int ret;

	reinit_completion(&pgp->ack);

	ret = pmic_glink_send(pgp->client, data, len);
	if (ret < 0)
		return ret;

	left = wait_for_completion_timeout(&pgp->ack, HZ);
	if (!left)
		return -ETIMEDOUT;

	return 0;
}

static int pmic_glink_ps_request(struct pmic_glink_power *pgp, int opcode,
				 int property, u32 value)
{
	struct pmic_glink_bat_req request = {
		.hdr.owner = cpu_to_le32(PMIC_GLINK_OWNER_BC),
		.hdr.type = cpu_to_le32(PMIC_GLINK_REQ_RESP),
		.hdr.opcode = cpu_to_le32(opcode),
		.battery = cpu_to_le32(0),
		.property = cpu_to_le32(property),
		.value = cpu_to_le32(value),
	};

	return pmic_glink_ps_send(pgp, &request, sizeof(request));
}

static int pmic_glink_bat_get(struct power_supply *psy,
			      enum power_supply_property psp,
			      union power_supply_propval *val)
{
	struct pmic_glink_power *pgp = power_supply_get_drvdata(psy);
	int prop;
	int ret;

	switch (psp) {
	case POWER_SUPPLY_PROP_STATUS:
		prop = BATT_STATUS;
		break;
	case POWER_SUPPLY_PROP_HEALTH:
		prop = BATT_HEALTH;
		break;
	case POWER_SUPPLY_PROP_PRESENT:
		prop = BATT_PRESENT;
		break;
	case POWER_SUPPLY_PROP_CHARGE_TYPE:
		prop = BATT_CHG_TYPE;
		break;
	case POWER_SUPPLY_PROP_CAPACITY:
		prop = BATT_CAPACITY;
		break;
	case POWER_SUPPLY_PROP_VOLTAGE_OCV:
		prop = BATT_VOLT_OCV;
		break;
	case POWER_SUPPLY_PROP_VOLTAGE_NOW:
		prop = BATT_VOLT_NOW;
		break;
	case POWER_SUPPLY_PROP_VOLTAGE_MAX:
		prop = BATT_VOLT_MAX;
		break;
	case POWER_SUPPLY_PROP_CURRENT_NOW:
		prop = BATT_CURR_NOW;
		break;
	case POWER_SUPPLY_PROP_CHARGE_CONTROL_LIMIT:
		prop = BATT_CHG_CTRL_LIM;
		break;
	case POWER_SUPPLY_PROP_CHARGE_CONTROL_LIMIT_MAX:
		prop = BATT_CHG_CTRL_LIM_MAX;
		break;
	case POWER_SUPPLY_PROP_TEMP:
		prop = BATT_TEMP;
		break;
	case POWER_SUPPLY_PROP_TECHNOLOGY:
		prop = BATT_TECHNOLOGY;
		break;
	case POWER_SUPPLY_PROP_CHARGE_COUNTER:
		prop = BATT_CHG_COUNTER;
		break;
	case POWER_SUPPLY_PROP_CYCLE_COUNT:
		prop = BATT_CYCLE_COUNT;
		break;
	case POWER_SUPPLY_PROP_CHARGE_FULL_DESIGN:
		prop = BATT_CHG_FULL_DESIGN;
		break;
	case POWER_SUPPLY_PROP_CHARGE_FULL:
		prop = BATT_CHG_FULL;
		break;
	case POWER_SUPPLY_PROP_MODEL_NAME:
		prop = BATT_MODEL_NAME;
		break;
	case POWER_SUPPLY_PROP_TIME_TO_FULL_AVG:
		prop = BATT_TTF_AVG;
		break;
	case POWER_SUPPLY_PROP_TIME_TO_EMPTY_AVG:
		prop = BATT_TTE_AVG;
		break;
	case POWER_SUPPLY_PROP_POWER_NOW:
		prop = BATT_POWER_NOW;
		break;
	case POWER_SUPPLY_PROP_POWER_AVG:
		prop = BATT_POWER_AVG;
		break;
	default:
		return -EINVAL;
	}

	mutex_lock(&pgp->lock);
	ret = pmic_glink_ps_request(pgp, BC_BATTERY_STATUS_GET, prop, 0);
	if (ret < 0)
		goto out_unlock;

	if (pgp->error) {
		ret = pgp->error;
		goto out_unlock;
	}

	switch (psp) {
	case POWER_SUPPLY_PROP_MODEL_NAME:
		val->strval = pgp->bat_model;
		break;
	case POWER_SUPPLY_PROP_CAPACITY:
		val->intval = pgp->value / 100;
		break;
	case POWER_SUPPLY_PROP_TEMP:
		val->intval = pgp->value / 10;
		break;
	default:
		val->intval = pgp->value;
		break;
	};

out_unlock:
	mutex_unlock(&pgp->lock);
	return ret;
}

static const enum power_supply_property bat_props[] = {
	POWER_SUPPLY_PROP_STATUS,
	POWER_SUPPLY_PROP_HEALTH,
	POWER_SUPPLY_PROP_PRESENT,
	POWER_SUPPLY_PROP_CHARGE_TYPE,
	POWER_SUPPLY_PROP_CAPACITY,
	POWER_SUPPLY_PROP_VOLTAGE_OCV,
	POWER_SUPPLY_PROP_VOLTAGE_NOW,
	POWER_SUPPLY_PROP_VOLTAGE_MAX,
	POWER_SUPPLY_PROP_CURRENT_NOW,
	POWER_SUPPLY_PROP_CHARGE_CONTROL_LIMIT,
	POWER_SUPPLY_PROP_CHARGE_CONTROL_LIMIT_MAX,
	POWER_SUPPLY_PROP_TEMP,
	POWER_SUPPLY_PROP_TECHNOLOGY,
	POWER_SUPPLY_PROP_CHARGE_COUNTER,
	POWER_SUPPLY_PROP_CYCLE_COUNT,
	POWER_SUPPLY_PROP_CHARGE_FULL_DESIGN,
	POWER_SUPPLY_PROP_CHARGE_FULL,
	POWER_SUPPLY_PROP_MODEL_NAME,
	POWER_SUPPLY_PROP_TIME_TO_FULL_AVG,
	POWER_SUPPLY_PROP_TIME_TO_EMPTY_AVG,
	POWER_SUPPLY_PROP_POWER_NOW,
	POWER_SUPPLY_PROP_POWER_AVG,
};

static const struct power_supply_desc bat_psy_desc = {
	.name = "battery",
	.type = POWER_SUPPLY_TYPE_BATTERY,
	.properties = bat_props,
	.num_properties = ARRAY_SIZE(bat_props),
	.get_property = pmic_glink_bat_get,
};

static int pmic_glink_ps_usb_get(struct power_supply *psy,
				 enum power_supply_property psp,
				 union power_supply_propval *val)
{
	struct pmic_glink_power *pgp = power_supply_get_drvdata(psy);
	int prop;
	int ret;

	switch (psp) {
	case POWER_SUPPLY_PROP_ONLINE:
		prop = USB_ONLINE;
		break;
	case POWER_SUPPLY_PROP_VOLTAGE_NOW:
		prop = USB_VOLT_NOW;
		break;
	case POWER_SUPPLY_PROP_VOLTAGE_MAX:
		prop = USB_VOLT_MAX;
		break;
	case POWER_SUPPLY_PROP_CURRENT_NOW:
		prop = USB_CURR_NOW;
		break;
	case POWER_SUPPLY_PROP_CURRENT_MAX:
		prop = USB_CURR_MAX;
		break;
	case POWER_SUPPLY_PROP_INPUT_CURRENT_LIMIT:
		prop = USB_INPUT_CURR_LIMIT;
		break;
	case POWER_SUPPLY_PROP_USB_TYPE:
		prop = USB_TYPE;
		break;
	default:
		return -EINVAL;
	}

	mutex_lock(&pgp->lock);
	ret = pmic_glink_ps_request(pgp, BC_USB_STATUS_GET, prop, 0);
	if (ret < 0)
		goto out_unlock;

	if (pgp->error)
		ret = pgp->error;
	else
		val->intval = pgp->value;

out_unlock:
	mutex_unlock(&pgp->lock);

	return ret;
}

static const enum power_supply_property usb_props[] = {
	POWER_SUPPLY_PROP_ONLINE,
	POWER_SUPPLY_PROP_VOLTAGE_NOW,
	POWER_SUPPLY_PROP_VOLTAGE_MAX,
	POWER_SUPPLY_PROP_CURRENT_NOW,
	POWER_SUPPLY_PROP_CURRENT_MAX,
	POWER_SUPPLY_PROP_INPUT_CURRENT_LIMIT,
	POWER_SUPPLY_PROP_USB_TYPE,
};

static const enum power_supply_usb_type usb_psy_supported_types[] = {
	POWER_SUPPLY_USB_TYPE_UNKNOWN,
	POWER_SUPPLY_USB_TYPE_SDP,
	POWER_SUPPLY_USB_TYPE_DCP,
	POWER_SUPPLY_USB_TYPE_CDP,
	POWER_SUPPLY_USB_TYPE_ACA,
	POWER_SUPPLY_USB_TYPE_C,
	POWER_SUPPLY_USB_TYPE_PD,
	POWER_SUPPLY_USB_TYPE_PD_DRP,
	POWER_SUPPLY_USB_TYPE_PD_PPS,
	POWER_SUPPLY_USB_TYPE_APPLE_BRICK_ID,
};

static const struct power_supply_desc usb_psy_desc = {
	.name = "usb",
	.type = POWER_SUPPLY_TYPE_USB,
	.properties = usb_props,
	.num_properties = ARRAY_SIZE(usb_props),
	.get_property = pmic_glink_ps_usb_get,
	.usb_types = usb_psy_supported_types,
	.num_usb_types = ARRAY_SIZE(usb_psy_supported_types),
};

static int pmic_glink_ps_wls_get(struct power_supply *psy,
				 enum power_supply_property psp,
				 union power_supply_propval *val)
{
	struct pmic_glink_power *pgp = power_supply_get_drvdata(psy);
	int prop;
	int ret;

	switch (psp) {
	case POWER_SUPPLY_PROP_ONLINE:
		prop = WLS_ONLINE;
		break;
	case POWER_SUPPLY_PROP_VOLTAGE_NOW:
		prop = WLS_VOLT_NOW;
		break;
	case POWER_SUPPLY_PROP_VOLTAGE_MAX:
		prop = WLS_VOLT_MAX;
		break;
	case POWER_SUPPLY_PROP_CURRENT_NOW:
		prop = WLS_CURR_NOW;
		break;
	case POWER_SUPPLY_PROP_CURRENT_MAX:
		prop = WLS_CURR_MAX;
		break;
	default:
		return -EINVAL;
	}

	mutex_lock(&pgp->lock);
	ret = pmic_glink_ps_request(pgp, BC_WLS_STATUS_GET, prop, 0);
	if (ret < 0)
		goto out_unlock;

	if (pgp->error)
		ret = pgp->error;
	else
		val->intval = pgp->value;

out_unlock:
	mutex_unlock(&pgp->lock);

	return ret;
}

static const enum power_supply_property wls_props[] = {
	POWER_SUPPLY_PROP_ONLINE,
	POWER_SUPPLY_PROP_VOLTAGE_NOW,
	POWER_SUPPLY_PROP_VOLTAGE_MAX,
	POWER_SUPPLY_PROP_CURRENT_NOW,
	POWER_SUPPLY_PROP_CURRENT_MAX,
};

static const struct power_supply_desc wls_psy_desc = {
	.name = "wireless",
	.type = POWER_SUPPLY_TYPE_WIRELESS,
	.properties = wls_props,
	.num_properties = ARRAY_SIZE(wls_props),
	.get_property = pmic_glink_ps_wls_get,
};

static void pmic_glink_ps_notification(struct pmic_glink_power *pgp,
				       const struct pmic_glink_bat_notification *msg,
				       int len)
{
	if (len != sizeof(*msg)) {
		dev_warn(pgp->dev, "ignoring notification with invalid length\n");
		return;
	}

	switch (le32_to_cpu(msg->notification)) {
	case BC_BATTERY_STATUS_GET:
		power_supply_changed(pgp->bat_psy);
		break;
	case BC_USB_STATUS_GET:
		power_supply_changed(pgp->usb_psy);
		break;
	case BC_WLS_STATUS_GET:
		power_supply_changed(pgp->wls_psy);
		break;
	}
}

static void pmic_glink_power_response(struct pmic_glink_power *pgp,
				      const struct pmic_glink_bat_resp *resp,
				      size_t len)
{
	unsigned int property;
	unsigned int opcode;
	size_t payload_len = len - sizeof(struct pmic_glink_hdr);

	if (payload_len < sizeof(__le32)) {
		dev_warn(pgp->dev, "ignoring response %u of invalid size %zd\n",
			 resp->hdr.opcode, len);
		return;
	}

	opcode = le32_to_cpu(resp->hdr.opcode);
	property = le32_to_cpu(resp->property);

	if (opcode == BC_BATTERY_STATUS_GET && property == BATT_MODEL_NAME) {
		if (payload_len != sizeof(__le32) + MODEL_NAME_LEN) {
			dev_warn(pgp->dev, "received short model response\n");
			pgp->bat_model[0] = '\0';
			pgp->error = -ENODATA;
		} else {
			strscpy(pgp->bat_model, resp->strval.model, sizeof(pgp->bat_model));
		}
	} else if (opcode == BC_SET_NOTIFY_REQ) {
		pgp->value = 0;
		pgp->error = 0;
	} else {
		if (payload_len != 3 * sizeof(__le32)) {
			dev_warn(pgp->dev,
				 "received response with invalid payload length %zd\n",
				 payload_len);
			pgp->error = -ENODATA;
		} else {
			pgp->value = le32_to_cpu(resp->intval.value);
			pgp->error = le32_to_cpu(resp->intval.result);
		}
	}

	complete(&pgp->ack);
}

static void pmic_glink_power_callback(const void *data, size_t len, void *priv)
{
	const struct pmic_glink_hdr *hdr = data;
	struct pmic_glink_power *pgp = priv;
	unsigned int opcode = le32_to_cpu(hdr->opcode);

	if (opcode == BC_NOTIFY_IND)
		pmic_glink_ps_notification(pgp, data, len);
	else
		pmic_glink_power_response(pgp, data, len);
}

static int pmic_glink_power_enable_notifications(struct pmic_glink_power *pgp)
{
	struct pmic_glink_bat_enable_notifications req = {
		.hdr.owner = PMIC_GLINK_OWNER_BC,
		.hdr.type = PMIC_GLINK_NOTIFY,
		.hdr.opcode = BC_SET_NOTIFY_REQ,
	};

	return pmic_glink_ps_send(pgp, &req, sizeof(req));
}

static int pmic_glink_ps_probe(struct auxiliary_device *adev,
			       const struct auxiliary_device_id *id)
{
	struct power_supply_config psy_cfg = {};
	struct pmic_glink_power *pgp;

	pgp = devm_kzalloc(&adev->dev, sizeof(*pgp), GFP_KERNEL);
	if (!pgp)
		return -ENOMEM;

	pgp->dev = &adev->dev;

	psy_cfg.drv_data = pgp;
	psy_cfg.of_node = adev->dev.of_node;

	mutex_init(&pgp->lock);
	init_completion(&pgp->ack);

	pgp->client = devm_pmic_glink_register_client(&adev->dev,
						      PMIC_GLINK_OWNER_BC,
						      pmic_glink_power_callback,
						      pgp);
	if (IS_ERR(pgp->client))
		return PTR_ERR(pgp->client);

	pgp->bat_psy = devm_power_supply_register(&adev->dev, &bat_psy_desc, &psy_cfg);
	if (IS_ERR(pgp->bat_psy))
		dev_err_probe(&adev->dev, PTR_ERR(pgp->bat_psy),
			      "failed to register battery power supply\n");

	pgp->usb_psy = devm_power_supply_register(&adev->dev, &usb_psy_desc, &psy_cfg);
	if (IS_ERR(pgp->usb_psy))
		dev_err_probe(&adev->dev, PTR_ERR(pgp->usb_psy),
			      "failed to register USB power supply\n");

	pgp->wls_psy = devm_power_supply_register(&adev->dev, &wls_psy_desc, &psy_cfg);
	if (IS_ERR(pgp->wls_psy))
		dev_err_probe(&adev->dev, PTR_ERR(pgp->wls_psy),
			      "failed to register wireless charing power supply\n");

	dev_set_drvdata(&adev->dev, pgp);

	return pmic_glink_power_enable_notifications(pgp);
}

static const struct auxiliary_device_id pmic_glink_ps_id_table[] = {
	{ .name = "pmic_glink.power-supply", },
	{},
};
MODULE_DEVICE_TABLE(auxiliary, pmic_glink_ps_id_table);

static struct auxiliary_driver pmic_glink_ps_driver = {
	.name = "pmic_glink_power_supply",
	.probe = pmic_glink_ps_probe,
	.id_table = pmic_glink_ps_id_table,
};

static int __init pmic_glink_ps_init(void)
{
	return auxiliary_driver_register(&pmic_glink_ps_driver);
}
module_init(pmic_glink_ps_init);

static void __exit pmic_glink_ps_exit(void)
{
	auxiliary_driver_unregister(&pmic_glink_ps_driver);
}
module_exit(pmic_glink_ps_exit);

MODULE_DESCRIPTION("Qualcomm PMIC GLINK power-supply driver");
MODULE_LICENSE("GPL v2");
