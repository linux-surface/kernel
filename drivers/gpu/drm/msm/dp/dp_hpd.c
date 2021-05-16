// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2012-2020, The Linux Foundation. All rights reserved.
 */

#define pr_fmt(fmt)	"[drm-dp] %s: " fmt, __func__

#include <linux/slab.h>
#include <linux/device.h>
#include <linux/usb/typec_altmode.h>
#include <linux/usb/typec_dp.h>
#include <linux/usb/typec_mux.h>

#include "dp_hpd.h"

/* DP specific VDM commands */
#define DP_USBPD_VDM_STATUS	0x10
#define DP_USBPD_VDM_CONFIGURE	0x11

/* USBPD-TypeC specific Macros */
#define VDM_VERSION		0x0
#define USB_C_DP_SID		0xFF01

struct dp_hpd_private {
	struct device *dev;
	struct dp_usbpd_cb *dp_cb;
	struct dp_usbpd dp_usbpd;
	struct typec_mux_dev *mux;
	bool connected;
};

int dp_hpd_connect(struct dp_usbpd *dp_usbpd, bool hpd)
{
	int rc = 0;
	struct dp_hpd_private *hpd_priv;

	hpd_priv = container_of(dp_usbpd, struct dp_hpd_private,
					dp_usbpd);

	if (!hpd_priv->dp_cb || !hpd_priv->dp_cb->configure
				|| !hpd_priv->dp_cb->disconnect) {
		pr_err("hpd dp_cb not initialized\n");
		return -EINVAL;
	}
	if (hpd)
		hpd_priv->dp_cb->configure(hpd_priv->dev);
	else
		hpd_priv->dp_cb->disconnect(hpd_priv->dev);

	return rc;
}

static int dp_hpd_mux_set(struct typec_mux_dev *mux, struct typec_mux_state *state)
{
	struct dp_hpd_private *dp_hpd = typec_mux_get_drvdata(mux);
	struct dp_usbpd *usbpd = &dp_hpd->dp_usbpd;
	struct typec_displayport_data *dp_data = state->data;
	int pin_assign = 0;

	if (dp_data) {
		pin_assign = DP_CONF_GET_PIN_ASSIGN(dp_data->conf);
		usbpd->hpd_irq = !!(dp_data->status & DP_STATUS_IRQ_HPD);
		usbpd->multi_func = pin_assign == DP_PIN_ASSIGN_C || DP_PIN_ASSIGN_E;
	}

	if (!pin_assign) {
		if (dp_hpd->connected) {
			dp_hpd->connected = false;
			dp_hpd->dp_cb->disconnect(dp_hpd->dev);
		}
	} else if (!dp_hpd->connected) {
		dp_hpd->connected = true;
		dp_hpd->dp_cb->configure(dp_hpd->dev);
	} else {
		dp_hpd->dp_cb->attention(dp_hpd->dev);
	}

	return 0;
}

static void dp_hpd_unregister_typec_mux(void *data)
{
	typec_mux_unregister(data);
}

struct dp_usbpd *dp_hpd_get(struct device *dev, struct dp_usbpd_cb *cb)
{
	struct typec_mux_desc mux_desc = {};
	struct dp_hpd_private *dp_hpd;
	int rc;

	if (!cb) {
		pr_err("invalid cb data\n");
		return ERR_PTR(-EINVAL);
	}

	dp_hpd = devm_kzalloc(dev, sizeof(*dp_hpd), GFP_KERNEL);
	if (!dp_hpd)
		return ERR_PTR(-ENOMEM);

	dp_hpd->dev = dev;
	dp_hpd->dp_cb = cb;

	dp_hpd->dp_usbpd.connect = dp_hpd_connect;

	mux_desc.fwnode = dev->fwnode;
	mux_desc.set = dp_hpd_mux_set;
	mux_desc.drvdata = dp_hpd;
	dp_hpd->mux = typec_mux_register(dev, &mux_desc);
	if (IS_ERR(dp_hpd->mux)) {
		dev_err(dev, "unable to register typec mux\n");
		return ERR_CAST(dp_hpd->mux);
	}

	rc = devm_add_action_or_reset(dev, dp_hpd_unregister_typec_mux, dp_hpd->mux);
	if (rc)
		return ERR_PTR(rc);

	return &dp_hpd->dp_usbpd;
}
