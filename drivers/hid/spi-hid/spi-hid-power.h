/*
 * spi-hid-power.h
 *
 * Copyright (c) 2020 Microsoft Corporation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

#ifndef SPI_HID_POWER_H
#define SPI_HID_POWER_H

#include <linux/pinctrl/consumer.h>

struct spi_hid_power {
	struct regulator *supply;
	struct pinctrl *pinctrl;
	struct pinctrl_state *pinctrl_reset;
	struct pinctrl_state *pinctrl_active;
	struct pinctrl_state *pinctrl_sleep;
};

static inline int spi_hid_power_init(struct spi_hid_power *pwr,
		struct device *dev)
{
	pwr->supply = devm_regulator_get(dev, "vdd");
	if (IS_ERR(pwr->supply)) {
		if (PTR_ERR(pwr->supply) != -EPROBE_DEFER)
			dev_err(dev, "Failed to get regulator: %d\n", PTR_ERR(pwr->supply));
		return PTR_ERR(pwr->supply);
	}

	pwr->pinctrl = devm_pinctrl_get(dev);
	if (IS_ERR_OR_NULL(pwr->pinctrl)) {
		dev_err(dev, "Could not get pinctrl handle: %d\n",
				pwr->pinctrl);
		return PTR_ERR(pwr->pinctrl);
	}
	pwr->pinctrl_reset = pinctrl_lookup_state(pwr->pinctrl, "reset");
	if (IS_ERR_OR_NULL(pwr->pinctrl)) {
		dev_err(dev, "Could not get pinctrl reset: %d\n",
				pwr->pinctrl);
		return PTR_ERR(pwr->pinctrl);
	}
	pwr->pinctrl_active = pinctrl_lookup_state(pwr->pinctrl, "active");
	if (IS_ERR_OR_NULL(pwr->pinctrl)) {
		dev_err(dev, "Could not get pinctrl active: %d\n",
				pwr->pinctrl);
		return PTR_ERR(pwr->pinctrl);
	}
	pwr->pinctrl_sleep = pinctrl_lookup_state(pwr->pinctrl, "sleep");
	if (IS_ERR_OR_NULL(pwr->pinctrl)) {
		dev_err(dev, "Could not get pinctrl sleep: %d\n",
				pwr->pinctrl);
		return PTR_ERR(pwr->pinctrl);
	}

	return pinctrl_select_state(pwr->pinctrl, pwr->pinctrl_sleep);;
}

static inline int spi_hid_power_up(struct spi_hid_power *pwr)
{
	int ret = regulator_enable(pwr->supply);
	if (ret) return ret;

	msleep(5); //Let VREG_TOUCH_1P8V stabilize

	ret = pinctrl_select_state(pwr->pinctrl, pwr->pinctrl_sleep);
	if (ret) return ret;

	msleep(5); //Let VREG_TOUCH_1P8V stabilize

	ret = pinctrl_select_state(pwr->pinctrl, pwr->pinctrl_reset);
	if (ret) return ret;

	msleep(2); //Let VDD_CORE stabilize

	return pinctrl_select_state(pwr->pinctrl, pwr->pinctrl_active);
}

static inline int spi_hid_power_down(struct spi_hid_power *pwr)
{
	pinctrl_select_state(pwr->pinctrl, pwr->pinctrl_sleep);
	return regulator_disable(pwr->supply);
}

static inline int spi_hid_power_reset(struct spi_hid_power *pwr)
{
	return pinctrl_select_state(pwr->pinctrl, pwr->pinctrl_reset);
}

static inline int spi_hid_power_restart(struct spi_hid_power *pwr)
{
	msleep(2); //Let VDD_CORE stabilize

	return pinctrl_select_state(pwr->pinctrl, pwr->pinctrl_active);
}

#endif