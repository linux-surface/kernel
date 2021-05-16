// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2012-2020, The Linux Foundation. All rights reserved.
 */

#define pr_fmt(fmt)	"[drm-dp] %s: " fmt, __func__

#include <linux/slab.h>
#include <linux/device.h>
#include <linux/usb/typec_altmode.h>
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
	struct typec_mux *mux;
	bool active;
};

int dp_hpd_connect(struct dp_usbpd *dp_usbpd, bool hpd)
{
	int rc = 0;
	struct dp_hpd_private *hpd_priv;

	hpd_priv = container_of(dp_usbpd, struct dp_hpd_private,
					dp_usbpd);

	dp_usbpd->hpd_high = hpd;

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

static int dp_hpd_mux_set(struct typec_mux *mux, struct typec_mux_state *state)
{
	struct dp_hpd_private *dp_hpd = typec_mux_get_drvdata(mux);	
	struct typec_altmode *alt = state->alt;

	dev_err(dp_hpd->dev, "%s() mode: %ld\n", __func__, state->mode);

	if (!alt) {
		dev_err(dp_hpd->dev, "%s() state->alt is NULL\n", __func__);
		return 0;
	}

	dev_err(dp_hpd->dev, "%s() svid: %#x\n", __func__, alt->svid);
	dev_err(dp_hpd->dev, "%s() mode: %d\n", __func__, alt->mode);
	dev_err(dp_hpd->dev, "%s() vdo: %#x\n", __func__, alt->vdo);
	dev_err(dp_hpd->dev, "%s() active: %d\n", __func__, alt->active);

	if (dp_hpd->active == alt->active)
		return 0;

	if (alt->active)
		dp_hpd->dp_cb->configure(dp_hpd->dev);
	else
		dp_hpd->dp_cb->disconnect(dp_hpd->dev);

	dp_hpd->active = alt->active;

	return 0;
}

struct dp_usbpd *dp_hpd_get(struct device *dev, struct dp_usbpd_cb *cb)
{
	struct typec_mux_desc mux_desc = {};
	struct dp_hpd_private *dp_hpd;

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

	return &dp_hpd->dp_usbpd;
}
